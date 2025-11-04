#!/usr/bin/env python3
import argparse
import asyncio
import contextlib
import json
import os
import signal
from typing import Optional

from websockets.server import Serve, WebSocketServerProtocol, serve
from websockets.exceptions import ConnectionClosed

async def async_entry_point() -> None:
    cli_parser = argparse.ArgumentParser(description="OrbitalRelay relay server")
    cli_parser.add_argument("--host", default="0.0.0.0", help="Bind host")
    cli_parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", 8080)), help="Bind port")
    cli_parser.add_argument("--password", default=os.environ.get("ORBITAL_RELAY_PASSWORD", ""), help="Shared SOCKS password")
    cli_parser.add_argument("--auth-token", default=os.environ.get("ORBITAL_RELAY_TOKEN", ""), help="Authorization token to expect in the Authorization header")
    cli_parser.add_argument("--handshake-timeout", type=float, default=float(os.environ.get("ORBITAL_HANDSHAKE_TIMEOUT", "5")), help="Seconds to wait for handshake before closing")

    cli_options = cli_parser.parse_args()

    fallback_service = UpstreamFallbackService(
        listen_address=cli_options.host,
        listen_port=cli_options.port,
        shared_credential=cli_options.password,
        api_key_secret=cli_options.auth_token,
        connect_negotiation_limit=cli_options.handshake_timeout,
    )

    await fallback_service.execute_service_loop()


class UpstreamFallbackService:
    def __init__(self, listen_address: str, listen_port: int, shared_credential: str, api_key_secret: Optional[str], connect_negotiation_limit: float) -> None:
        self.listen_address = listen_address
        self.listen_port = listen_port
        self.shared_credential = shared_credential
        self.api_key_secret = api_key_secret or ""
        self.connect_negotiation_limit = connect_negotiation_limit
        self._service_instance: Optional[Serve] = None

    async def execute_service_loop(self) -> None:
        await self.launch_service()
        shutdown_signal_event = asyncio.Event()

        def _trigger_shutdown(*_: object) -> None:
            shutdown_signal_event.set()

        event_loop = asyncio.get_running_loop()
        for signal_type in (signal.SIGINT, signal.SIGTERM):
            event_loop.add_signal_handler(signal_type, _trigger_shutdown)

        print(f"🚀 OrbitalRelay server running on {self.listen_address}:{self.listen_port}...")
        await shutdown_signal_event.wait()
        print("\nShutting down server...")
        await self.shutdown_service()

    async def launch_service(self) -> None:
        self._service_instance = await serve(
            self._manage_new_connection,
            self.listen_address,
            self.listen_port,
            process_request=self._pre_upgrade_validation,
            max_size=None,
        )

    async def shutdown_service(self) -> None:
        if self._service_instance is not None:
            self._service_instance.close()
            await self._service_instance.wait_closed()
            self._service_instance = None

    async def _pre_upgrade_validation(self, request_path, http_headers):
        if self.api_key_secret:
            auth_header_value = http_headers.get("Authorization", "")

            if auth_header_value.startswith("Bearer "):
                auth_header_value = auth_header_value[7:]

            if auth_header_value != self.api_key_secret:
                error_payload = b"Unauthorized"
                return (401, [("Content-Type", "text/plain"), ("Content-Length", str(len(error_payload)))], error_payload)
        return None

    async def _manage_new_connection(self, client_ws: WebSocketServerProtocol, ws_path: str = "") -> None:
        upstream_reader: Optional[asyncio.StreamReader] = None
        upstream_writer: Optional[asyncio.StreamWriter] = None
        
        ws_closed = False

        try:
            try:
                initial_data = await asyncio.wait_for(client_ws.recv(), timeout=self.connect_negotiation_limit)
            except Exception:
                await client_ws.close(code=4000, reason="Handshake timeout")
                ws_closed = True
                return

            if isinstance(initial_data, (bytes, bytearray, memoryview)):
                await client_ws.close(code=4001, reason="Invalid handshake payload")
                ws_closed = True
                return

            try:
                connect_params = json.loads(initial_data)
            except json.JSONDecodeError:
                await client_ws.close(code=4002, reason="Invalid handshake JSON")
                ws_closed = True
                return

            if not isinstance(connect_params, dict):
                await client_ws.close(code=4003, reason="Invalid handshake format")
                ws_closed = True
                return

            destination_host = connect_params.get("hostname")
            destination_port = connect_params.get("port")
            client_credential = connect_params.get("password")

            if not destination_host or not isinstance(destination_host, str):
                await client_ws.send(json.dumps({"type": "error", "code": "invalid-target", "message": "Missing hostname"}))
                await client_ws.close(code=4004, reason="Missing hostname")
                ws_closed = True
                return

            if not isinstance(destination_port, int) or destination_port < 1 or destination_port > 65535:
                await client_ws.send(json.dumps({"type": "error", "code": "invalid-target", "message": "Invalid port"}))
                await client_ws.close(code=4005, reason="Invalid port")
                ws_closed = True
                return

            if self.shared_credential and client_credential != self.shared_credential:
                await client_ws.send(json.dumps({"type": "error", "code": "auth-failed", "message": "Invalid credentials"}))
                await client_ws.close(code=4006, reason="Auth failed")
                ws_closed = True
                return

            try:
                upstream_reader, upstream_writer = await asyncio.open_connection(destination_host, destination_port)
            except Exception as exc:
                await client_ws.send(json.dumps({
                    "type": "error",
                    "code": "connect-failed",
                    "message": str(exc) or "Failed to connect upstream"
                }))
                await client_ws.close(code=4007, reason="Upstream connect failed")
                ws_closed = True
                return

            await client_ws.send(json.dumps({"type": "ready"}))

            bridge_tasks = [
                asyncio.create_task(self._forward_client_to_upstream(client_ws, upstream_writer)),
                asyncio.create_task(self._forward_upstream_to_client(client_ws, upstream_reader))
            ]
            completed, active = await asyncio.wait(bridge_tasks, return_when=asyncio.FIRST_COMPLETED)

            for active_task in active:
                active_task.cancel()
            await asyncio.gather(*active, return_exceptions=True)

            for active_task in completed:
                with contextlib.suppress(Exception):
                    active_task.result()
            
            # FINAL FIX: Mark as closed on normal completion
            # This prevents the finally block from attempting a redundant close
            ws_closed = True

        except (ConnectionClosed, ConnectionResetError, OSError):
            # Network error during bridging, connection is already gone
            ws_closed = True # Mark as closed
        except Exception as e:
            # Unexpected internal error
            with contextlib.suppress(ConnectionClosed):
                await client_ws.close(code=1011, reason=f"Internal server error: {e}")
                ws_closed = True # Mark as closed
        finally:
            # Clean up upstream connection
            if upstream_writer is not None:
                upstream_writer.close()
                with contextlib.suppress(Exception):
                    await upstream_writer.wait_closed()
            
            # Clean up WebSocket only if it wasn't already closed
            if not ws_closed:
                with contextlib.suppress(ConnectionClosed):
                    await client_ws.close(code=1000, reason="Connection finished")


    async def _forward_client_to_upstream(self, client_ws: WebSocketServerProtocol, upstream_writer: asyncio.StreamWriter) -> None:
        try:
            while True:
                client_data = await client_ws.recv()
                if isinstance(client_data, str):
                    upstream_writer.write(client_data.encode("utf-8"))
                else:
                    upstream_writer.write(client_data)
                await upstream_writer.drain()
        except (ConnectionClosed, ConnectionResetError, OSError):
            pass

    async def _forward_upstream_to_client(self, client_ws: WebSocketServerProtocol, upstream_reader: asyncio.StreamReader) -> None:
        try:
            upstream_data_chunk = await upstream_reader.read(65536)
            while upstream_data_chunk:
                await client_ws.send(upstream_data_chunk)
                upstream_data_chunk = await upstream_reader.read(65536)
        except (ConnectionClosed, ConnectionResetError, OSError):
            pass


if __name__ == "__main__":
    try:
        asyncio.run(async_entry_point())
    except KeyboardInterrupt:
        pass
