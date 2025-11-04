#!/usr/bin/env python3

import argparse
import asyncio
import getpass
import json
import os
import random
import secrets
import requests
import string
import socket
import struct
import subprocess
import time
import contextlib
# <-- FIX: Added Callable to import
from typing import Callable, Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse

from websockets.exceptions import ConnectionClosed
from websockets.legacy.client import WebSocketClientProtocol, connect as ws_connect
import ipaddress


g_resolution_ledger: Dict[str, Tuple[str, float]] = {}
G_RESOLUTION_EXPIRATION_SEC = 300


class DirectorAppError(Exception):
    pass


class ServiceMustUseRelay(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class UpstreamConnectionFailure(Exception):
    pass


class WorkerServiceManager:

    def __init__(
        self,
        auth_secret: str,
        org_identifier: str,
        domain_zone_id: Optional[str] = None,
        service_config: Optional[Dict] = None
    ):
        self.api_key = auth_secret
        self.org_id = org_identifier
        self.zone_identifier = domain_zone_id
        self.api_endpoint_base = "https://api.cloudflare.com/client/v4"
        self.request_auth_headers = {
            "Authorization": f"Bearer {auth_secret}",
            "Content-Type": "application/json"
        }
        self._org_host_prefix = None
        self.service_parameters = service_config or {}

    @property
    def service_host_prefix(self) -> str:
        if self._org_host_prefix:
            return self._org_host_prefix

        subdomain_api_url = f"{self.api_endpoint_base}/accounts/{self.org_id}/workers/subdomain"
        try:
            http_resp = requests.get(subdomain_api_url, headers=self.request_auth_headers, timeout=30)
            if http_resp.status_code == 200:
                json_payload = http_resp.json()
                host_prefix_str = json_payload.get("result", {}).get("subdomain")
                if host_prefix_str:
                    self._org_host_prefix = host_prefix_str
                    return host_prefix_str
        except requests.RequestException:
            pass

        self._org_host_prefix = self.org_id.lower()
        return self._org_host_prefix

    def _create_unique_service_id(self) -> str:
        time_marker = str(int(time.time()))
        entropy_suffix = ''.join(random.choices(string.ascii_lowercase, k=6))
        # RENAMED
        return f"orbital-relay-{time_marker}-{entropy_suffix}"

    def _get_http_worker_script(self) -> str:
        return """
export default {
  async fetch(req) {
    try {
      const reqUrl = new URL(req.url);
      const destinationUrl = getTargetUrl(reqUrl, req.headers);
      if (!destinationUrl) {
        return createErrorResponse('No target URL specified', {
          usage: {
            query_param: '?url=https://example.com',
            header: 'X-Target-URL: https://example.com',
            path: '/https://example.com'
          }
        }, 400);
      }

      let destinationUrlObj;
      try { destinationUrlObj = new URL(destinationUrl); }
      catch (e) { return createErrorResponse('Invalid target URL', { provided: destinationUrl }, 400); }

      const destinationParams = new URLSearchParams();
      for (const [key, value] of reqUrl.searchParams) {
        if (!['url', '_cb', '_t'].includes(key)) {
          destinationParams.append(key, value);
        }
      }
      if (destinationParams.toString()) {
        destinationUrlObj.search = destinationParams.toString();
      }

      const fwdReq = createProxyRequest(req, destinationUrlObj);
      const originResp = await fetch(fwdReq);
      return createProxyResponse(originResp, req.method);
    } catch (error) {
      return createErrorResponse('Proxy request failed', { message: error.message, timestamp: new Date().toISOString() }, 500);
    }
  }
}

function getTargetUrl(reqUrl, headers) {
  let destinationUrl = reqUrl.searchParams.get('url');
  if (!destinationUrl) destinationUrl = headers.get('X-Target-URL');
  if (!destinationUrl && reqUrl.pathname !== '/') {
    const pathUrl = reqUrl.pathname.slice(1);
    if (pathUrl.startsWith('http')) destinationUrl = pathUrl;
  }
  return destinationUrl;
}

function createProxyRequest(req, destinationUrlObj) {
  const fwdHeaders = new Headers();
  const passThroughHeaders = ['accept','accept-language','accept-encoding','authorization','cache-control','content-type','origin','referer','user-agent'];
  for (const [key, value] of req.headers) {
    if (passThroughHeaders.includes(key.toLowerCase())) fwdHeaders.set(key, value);
  }
  fwdHeaders.set('Host', destinationUrlObj.hostname);
  const customIp = req.headers.get('X-My-X-Forwarded-For');
  fwdHeaders.set('X-Forwarded-For', customIp || generateRandomIP());
  return new Request(destinationUrlObj.toString(), { method: req.method, headers: fwdHeaders, body: ['GET','HEAD'].includes(req.method) ? null : req.body });
}

function createProxyResponse(originResp, requestMethod) {
  const proxyRespHeaders = new Headers();
  for (const [key, value] of originResp.headers) {
    if (!['content-encoding','content-length','transfer-encoding'].includes(key.toLowerCase())) {
      proxyRespHeaders.set(key, value);
    }
  }
  proxyRespHeaders.set('Access-Control-Allow-Origin', '*');
  proxyRespHeaders.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, PATCH, HEAD');
  proxyRespHeaders.set('Access-Control-Allow-Headers', '*');
  if (requestMethod === 'OPTIONS') return new Response(null, { status: 204, headers: proxyRespHeaders });
  return new Response(originResp.body, { status: originResp.status, statusText: originResp.statusText, headers: proxyRespHeaders });
}

function createErrorResponse(error, details, status) {
  return new Response(JSON.stringify({ error, ...details }), { status, headers: { 'Content-Type': 'application/json' } });
}

function generateRandomIP() {
  return [1,2,3,4].map(() => Math.floor(Math.random()*255)+1).join('.');
}
"""

    def _get_socks_worker_script(self) -> str:
        api_key = json.dumps(self.service_parameters.get("auth_token", ""))
        tunnel_password = json.dumps(self.service_parameters.get("socks_password", ""))
        
        return ("""
import { connect } from 'cloudflare:sockets';

const API_KEY = SECURE_KEY_HOLDER;
const TUNNEL_PASSWORD = TUNNEL_SECRET_HOLDER;
const textEncoder = new TextEncoder();

export default {
  async fetch(req) {
    if (API_KEY && req.headers.get('Authorization') !== API_KEY) {
      return new Response('Unauthorized', { status: 401 });
    }
    if (req.headers.get('Upgrade') !== 'websocket') {
      return new Response('Expected Upgrade: websocket', { status: 426 });
    }

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    server.accept();
    server.binaryType = 'arraybuffer';

    server.addEventListener('message', async ({ data }) => {
      try {
        if (typeof data !== 'string') { server.close(1003, 'Invalid request'); return; }
        const connectArgs = JSON.parse(data);
        const targetHost = connectArgs.hostname;
        const targetPort = Number(connectArgs.port);
        const providedPsw = connectArgs.password ?? connectArgs.psw ?? '';
        if (!targetHost || !Number.isInteger(targetPort) || targetPort < 1 || targetPort > 65535) { server.close(1008, 'Invalid target'); return; }
        if (TUNNEL_PASSWORD && providedPsw !== TUNNEL_PASSWORD) { server.close(1008, 'Invalid credentials'); return; }

        let upstreamSocket;
        try { upstreamSocket = connect({ hostname: targetHost, port: targetPort }); }
        catch (e) { server.close(1011, 'Upstream connect failed'); return; }

        try { server.send(JSON.stringify({ type: 'ready' })); } catch (_) {}

        const clientDataStream = new ReadableStream({
          start(controller) {
            server.addEventListener('message', event => {
              const p = event.data;
              if (typeof p === 'string') controller.enqueue(textEncoder.encode(p));
              else if (p instanceof ArrayBuffer) controller.enqueue(new Uint8Array(p));
            });
            server.addEventListener('error', ev => controller.error(ev));
            server.addEventListener('close', () => controller.close());
          },
          cancel() { try { upstreamSocket && upstreamSocket.close && upstreamSocket.close(); } catch (_) {} }
        });

        clientDataStream.pipeTo(upstreamSocket.writable).catch(() => server.close(1011, 'Client error'));
        upstreamSocket.readable.pipeTo(new WritableStream({
          write(chunk) { server.send(chunk instanceof ArrayBuffer ? chunk : new Uint8Array(chunk)); },
          close() { server.close(); },
          abort() { server.close(1011, 'Upstream aborted'); }
        })).catch(() => server.close(1011, 'Upstream error'));
      } catch (e) { server.close(1003, 'Invalid request'); }
    }, { once: true });

    return new Response(null, { status: 101, webSocket: client });
  }
}
"""
        ).replace("SECURE_KEY_HOLDER", api_key).replace("TUNNEL_SECRET_HOLDER", tunnel_password)


    def _retrieve_service_code(self) -> str:
        service_type = (self.service_parameters.get("mode") or "http").lower()
        
        script_map = {
            "http": self._get_http_worker_script,
            "socks": self._get_socks_worker_script
        }
        
        getter_func = script_map.get(service_type, self._get_http_worker_script)
        return getter_func()

    def provision_new_service(self, service_id: Optional[str] = None) -> Dict:
        if not service_id:
            service_id = self._create_unique_service_id()

        service_source_code = self._retrieve_service_code()
        deployment_api_url = f"{self.api_endpoint_base}/accounts/{self.org_id}/workers/scripts/{service_id}"

        compat_options = self.service_parameters.get("compatibility_flags", ["nodejs_compat"])
        if isinstance(compat_options, str):
            compat_options = [compat_options]
        elif not isinstance(compat_options, list):
            compat_options = ["nodejs_compat"]

        config_metadata = {
            "main_module": "worker.js",
            "compatibility_date": self.service_parameters.get("compatibility_date", "2023-09-04"),
            "compatibility_flags": compat_options
        }

        multipart_payload = {
            'metadata': (None, json.dumps(config_metadata), 'application/json'),
            'worker.js': ('worker.js', service_source_code, 'application/javascript+module')
        }

        upload_http_headers = {"Authorization": f"Bearer {self.api_key}"}

        try:
            # Increased timeout for worker deployment
            http_resp = requests.put(deployment_api_url, headers=upload_http_headers, files=multipart_payload, timeout=90)
            http_resp.raise_for_status()
        except requests.HTTPError as e:
            error_message = ""
            if e.response is not None:
                try:
                    error_json = e.response.json()
                    api_errors = error_json.get("errors") if isinstance(error_json, dict) else None
                    if api_errors:
                        error_message = json.dumps(api_errors)
                    elif error_json:
                        error_message = json.dumps(error_json)
                except (ValueError, AttributeError):
                    error_message = e.response.text
            failure_reason = error_message or str(e)
            raise DirectorAppError(f"Failed to create worker: {failure_reason}")
        except requests.RequestException as e:
            raise DirectorAppError(f"Failed to create worker: {e}")

        provisioning_response = http_resp.json()

        subdomain_enable_url = f"{self.api_endpoint_base}/accounts/{self.org_id}/workers/scripts/{service_id}/subdomain"
        try:
            requests.post(subdomain_enable_url, headers=self.request_auth_headers, json={"enabled": True}, timeout=30)
        except requests.RequestException:
            pass

        service_endpoint_url = f"https://{service_id}.{self.service_host_prefix}.workers.dev"

        return {
            "name": service_id,
            "url": service_endpoint_url,
            "created_at": time.strftime('%Y-%m-%d %H:%M:%S'),
            "id": provisioning_response.get("result", {}).get("id", service_id),
            "auth_token": self.service_parameters.get("auth_token", ""),
            "socks_password": self.service_parameters.get("socks_password", "")
        }

    def enumerate_all_services(self) -> List[Dict]:
        list_api_url = f"{self.api_endpoint_base}/accounts/{self.org_id}/workers/scripts"

        try:
            http_resp = requests.get(list_api_url, headers=self.request_auth_headers, timeout=30)
            http_resp.raise_for_status()
        except requests.RequestException as e:
            raise DirectorAppError(f"Failed to list workers: {e}")

        json_payload = http_resp.json()
        found_services = []

        for service_record in json_payload.get("result", []):
            service_id = service_record.get("id", "")
            if service_id.startswith("orbital-relay-"):
                found_services.append({
                    "name": service_id,
                    "url": f"https://{service_id}.{self.service_host_prefix}.workers.dev",
                    "created_at": service_record.get("created_on", "unknown")
                })

        return found_services

    def validate_service_endpoint(self, service_endpoint_url: str, destination_url: str, http_verb: str = "GET") -> Dict:
        validation_url = f"{service_endpoint_url}?url={destination_url}"

        try:
            # Use the increased timeout here as well
            http_resp = requests.request(http_verb, validation_url, timeout=45) # <-- FIX: Increased timeout
            return {
                "success": True,
                "status_code": http_resp.status_code,
                "response_length": len(http_resp.content),
                "headers": dict(http_resp.headers)
            }
        except requests.RequestException as e:
            return {
                "success": False,
                "error": str(e)
            }

    def deprovision_all_services(self) -> None:
        services_to_delete = self.enumerate_all_services()

        for service_record in services_to_delete:
            delete_api_url = f"{self.api_endpoint_base}/accounts/{self.org_id}/workers/scripts/{service_record['name']}"
            try:
                http_resp = requests.delete(delete_api_url, headers=self.request_auth_headers, timeout=30)
                if http_resp.status_code in [200, 404]:
                    print(f"Deleted worker: {service_record['name']}")
                else:
                    print(f"Could not delete worker: {service_record['name']}")
            except requests.RequestException:
                print(f"Error deleting worker: {service_record['name']}")


class LocalTunnelGateway:
    def __init__(self, service_details: Dict, global_service_params: Dict, local_client_params: Dict, listen_address: str):
        self.service_config = dict(service_details)
        self.listen_host = listen_address
        self.api_secret_key = self.service_config.get("auth_token") or global_service_params.get("auth_token", "")
        self.tunnel_credential = self.service_config.get("socks_password") or global_service_params.get("socks_password", "")
        self.ws_connect_url = self._convert_http_to_ws_url(self.service_config.get("url", ""))
        self.service_name = self.service_config.get("name", "unknown")
        self._listener_task: Optional[asyncio.AbstractServer] = None
        self.listen_port: Optional[int] = None
        self.service_ip_override = (local_client_params.get("cf_override_ip") or "").strip()
        self.service_host_patterns = [h.lower() for h in local_client_params.get("cf_hostnames", []) if isinstance(h, str)]
        fallback_params = local_client_params.get("relay") if isinstance(local_client_params.get("relay"), dict) else {}
        self.fallback_config = dict(fallback_params)
        self.fallback_ws_url = (self.fallback_config.get("url") or "").strip()
        self.fallback_api_key = (self.fallback_config.get("auth_token") or "").strip()
        fallback_credential_str = (self.fallback_config.get("socks_password") or "").strip()
        self.fallback_credential = fallback_credential_str or self.tunnel_credential
        self.is_fallback_enabled = bool(self.fallback_config.get("enabled")) and bool(self.fallback_ws_url)
        self.upstream_ack_timeout = float(self.fallback_config.get("handshake_timeout", local_client_params.get("handshake_timeout", 5.0)))
        
        retry_buffer_max = self.fallback_config.get("retry_buffer_bytes", 262144)
        try:
            retry_buffer_max = int(retry_buffer_max)
        except (TypeError, ValueError):
            retry_buffer_max = 262144
        self.retry_buffer_size = max(0, retry_buffer_max)
        
        self.enable_secure_dns = bool(local_client_params.get("use_doh", True))
        self.secure_dns_timeout = float(local_client_params.get("doh_timeout", 5.0))

    class _ConnectionStartState:
        def __init__(self, max_size: int) -> None:
            self.max_size = max(0, int(max_size))
            self._buffered_chunks: List[bytes] = []
            self._bytes_buffered = 0
            self._buffer_sent = False
            self.connection_active = False

        def buffer_data(self, data_chunk: bytes) -> None:
            if self.connection_active or self._buffer_sent or self.max_size == 0 or not data_chunk:
                return
            space_remaining = self.max_size - self._bytes_buffered
            if space_remaining <= 0:
                return
            data_segment = bytes(data_chunk[:space_remaining])
            if data_segment:
                self._buffered_chunks.append(data_segment)
                self._bytes_buffered += len(data_segment)

        def set_connection_active(self) -> None:
            if not self.connection_active:
                self.connection_active = True
                self._buffered_chunks.clear()

        @property
        def can_retry_with_buffer(self) -> bool:
            return not self.connection_active and not self._buffer_sent and bool(self._buffered_chunks)

        def get_buffered_data(self) -> List[bytes]:
            if not self.can_retry_with_buffer:
                return []
            self._buffer_sent = True
            buffered_list = list(self._buffered_chunks)
            self._buffered_chunks.clear()
            return buffered_list

    @staticmethod
    def _decode_upstream_command(raw_message: str) -> Optional[Dict]:
        if not raw_message or len(raw_message) > 65536:
            return None
        try:
            json_payload = json.loads(raw_message)
        except (TypeError, ValueError):
            return None

        if isinstance(json_payload, dict) and isinstance(json_payload.get("type"), str):
            return json_payload
        return None

    @staticmethod
    def _convert_http_to_ws_url(http_url_str: str) -> str:
        url_parts = urlparse(http_url_str)
        ws_protocol = 'wss' if url_parts.scheme == 'https' else 'ws'
        url_path_query = url_parts.path or ''
        if url_parts.query:
            url_path_query = f"{url_path_query}?{url_parts.query}"
        if not url_parts.netloc:
            return http_url_str
        return f"{ws_protocol}://{url_parts.netloc}{url_path_query}"

    async def begin_listening(self, requested_port: Optional[int] = None) -> None:
        if not self.ws_connect_url:
            raise DirectorAppError(f"Endpoint {self.service_name} does not have a valid URL.")

        port_to_bind = requested_port if requested_port not in (None, 0) else 0

        try:
            self._listener_task = await asyncio.start_server(self._on_new_client_connection, self.listen_host, port_to_bind)
        except OSError:
            if port_to_bind != 0:
                self._listener_task = await asyncio.start_server(self._on_new_client_connection, self.listen_host, 0)
            else:
                raise

        sock = self._listener_task.sockets[0].getsockname()
        self.listen_port = sock[1]

    async def stop_listening(self) -> None:
        if self._listener_task:
            self._listener_task.close()
            await self._listener_task.wait_closed()
            self._listener_task = None

    async def _on_new_client_connection(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter) -> None:
        upstream_ws: Optional[WebSocketClientProtocol] = None
        client_address = client_writer.get_extra_info('peername', 'unknown')

        try:
            negotiation_result = await self._perform_socks_handshake(client_reader, client_writer)
            if not negotiation_result:
                return

            target_host, target_port, socks_req_data = negotiation_result
            
            host_for_upstream = target_host
            if self.service_ip_override and self._is_host_in_service_list(target_host.lower()):
                host_for_upstream = self.service_ip_override

            try:
                upstream_ws, connection_path = await self._establish_upstream_connection(
                    host_for_upstream, target_host, target_port
                )
            except UpstreamConnectionFailure:
                await self._respond_socks_failure(client_writer)
                return

            await self._respond_socks_success(client_writer, socks_req_data)

            upstream_ws = await self._relay_client_and_upstream(
                client_reader,
                client_writer,
                upstream_ws,
                connection_path,
                target_host,
                target_port
            )

        except Exception:
            pass
        finally:
            with contextlib.suppress(Exception):
                if upstream_ws is not None:
                    await upstream_ws.close()
            with contextlib.suppress(Exception):
                client_writer.close()
                await client_writer.wait_closed()

    async def _perform_socks_handshake(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter) -> Optional[Tuple[str, int, bytes]]:
        try:
            version_info = await client_reader.readexactly(2)
        except asyncio.IncompleteReadError:
            return None

        socks_version, auth_method_count = version_info
        if socks_version != 5:
            return None

        try:
            await client_reader.readexactly(auth_method_count)
        except asyncio.IncompleteReadError:
            return None

        client_writer.write(b"\x05\x00")
        await client_writer.drain()

        try:
            socks_req_header = await client_reader.readexactly(4)
        except asyncio.IncompleteReadError:
            return None

        req_version, req_command, _, req_addr_type = socks_req_header
        if req_version != 5 or req_command != 1:
            await self._respond_socks_failure(client_writer, 0x07)
            return None

        full_socks_request = bytearray(socks_req_header)
        
        addr_type_map = {
            1: (4, socket.inet_ntoa),
            3: -1,
            4: (16, lambda b: socket.inet_ntop(socket.AF_INET6, b))
        }

        try:
            if req_addr_type not in addr_type_map:
                await self._respond_socks_failure(client_writer, 0x08)
                return None

            if req_addr_type == 3:
                domain_len_bytes = await client_reader.readexactly(1)
                addr_bytes = await client_reader.readexactly(domain_len_bytes[0])
                target_host = addr_bytes.decode("utf-8")
                full_socks_request.extend(domain_len_bytes)
                full_socks_request.extend(addr_bytes)
            else:
                read_len, decoder = addr_type_map[req_addr_type]
                addr_bytes = await client_reader.readexactly(read_len)
                target_host = decoder(addr_bytes)
                full_socks_request.extend(addr_bytes)

            port_bytes = await client_reader.readexactly(2)
            target_port = struct.unpack(">H", port_bytes)[0]
            full_socks_request.extend(port_bytes)
        except asyncio.IncompleteReadError:
            return None

        if target_port <= 0 or target_port > 65535:
            await self._respond_socks_failure(client_writer, 0x09)
            return None

        return target_host, target_port, bytes(full_socks_request)

    async def _relay_client_and_upstream(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        upstream_ws: WebSocketClientProtocol,
        connection_path: str,
        target_host: str,
        target_port: int
    ) -> Optional[WebSocketClientProtocol]:
        current_upstream_ws = upstream_ws
        current_path = connection_path
        connection_state = self._ConnectionStartState(self.retry_buffer_size)
        relay_was_used = current_path != "worker"

        client_read_task = asyncio.create_task(client_reader.read(65536), name=f"client-{target_host}")
        upstream_read_task = asyncio.create_task(current_upstream_ws.recv(), name=f"upstream-{target_host}")

        async def failover_to_fallback(failover_reason: str) -> None:
            nonlocal current_upstream_ws, current_path, relay_was_used, client_read_task, upstream_read_task

            if relay_was_used:
                raise UpstreamConnectionFailure(failover_reason)
            if not self.is_fallback_enabled:
                raise UpstreamConnectionFailure(failover_reason)

            buffered_client_data = connection_state.get_buffered_data()

            previous_client_task = client_read_task
            previous_upstream_task = upstream_read_task

            if previous_client_task and not previous_client_task.done():
                previous_client_task.cancel()
                with contextlib.suppress(Exception):
                    await previous_client_task

            if previous_upstream_task and not previous_upstream_task.done():
                previous_upstream_task.cancel()
                with contextlib.suppress(Exception):
                    await previous_upstream_task

            with contextlib.suppress(Exception):
                await current_upstream_ws.close()

            current_upstream_ws = await self._establish_fallback_connection(target_host, target_port)
            
            if buffered_client_data:
                for data_chunk in buffered_client_data:
                    if data_chunk:
                        await current_upstream_ws.send(data_chunk)
                print(f"{self.service_name}: retry via relay ({failover_reason}) for {target_host}:{target_port} with {sum(len(s) for s in buffered_client_data)} bytes buffered")
            else:
                print(f"{self.service_name}: retry via relay ({failover_reason}) for {target_host}:{target_port} - fresh connection, no buffered data")

            current_path = "relay"
            relay_was_used = True
            client_read_task = asyncio.create_task(client_reader.read(65536), name=f"client-{target_host}")
            upstream_read_task = asyncio.create_task(current_upstream_ws.recv(), name=f"upstream-{target_host}")

        try:
            while True:
                completed_tasks, _ = await asyncio.wait(
                    [client_read_task, upstream_read_task],
                    return_when=asyncio.FIRST_COMPLETED
                )

                client_task_finished = client_read_task in completed_tasks
                upstream_task_finished = upstream_read_task in completed_tasks

                if upstream_task_finished:
                    try:
                        upstream_message = upstream_read_task.result()
                    except (ConnectionClosed, OSError, asyncio.IncompleteReadError, Exception) as error:
                        if (
                            current_path == "worker"
                            and not connection_state.connection_active
                            and self.is_fallback_enabled
                        ):
                            if client_task_finished:
                                try:
                                    if client_read_task.exception() is None:
                                        client_data_buffer = client_read_task.result()
                                        if client_data_buffer:
                                            connection_state.buffer_data(client_data_buffer)
                                except Exception:
                                    pass
                            try:
                                error_reason = f"worker connection lost: {type(error).__name__}"
                                await failover_to_fallback(error_reason)
                                continue
                            except UpstreamConnectionFailure as fallback_exc:
                                raise fallback_exc from error
                        if connection_state.connection_active:
                            break
                        raise UpstreamConnectionFailure(f"Upstream connection failed: {error}") from error

                    data_to_client = None
                    if isinstance(upstream_message, str):
                        if not connection_state.connection_active:
                            upstream_command = self._decode_upstream_command(upstream_message)
                            if upstream_command:
                                command_type = upstream_command.get("type")
                                error_reason = upstream_command.get("message") or upstream_command.get("code") or "Upstream reported error"
                                if command_type == "error":
                                    if current_path == "worker" and not relay_was_used:
                                        try:
                                            await failover_to_fallback(error_reason)
                                            continue
                                        except UpstreamConnectionFailure as fallback_exc:
                                            raise fallback_exc
                                    raise UpstreamConnectionFailure(error_reason)
                                if command_type == "ready":
                                    upstream_read_task = asyncio.create_task(current_upstream_ws.recv(), name=f"upstream-{target_host}")
                                else:
                                    upstream_read_task = asyncio.create_task(current_upstream_ws.recv(), name=f"upstream-{target_host}")
                            
                        else:
                            data_to_client = upstream_message.encode("utf-8")
                    else:
                        data_to_client = upstream_message

                    if data_to_client:
                        connection_state.set_connection_active()
                        try:
                            client_writer.write(data_to_client)
                            await client_writer.drain()
                        except Exception as exc:
                            raise UpstreamConnectionFailure("Failed to forward upstream data to client") from exc
                    
                    if current_upstream_ws is not None:
                        upstream_read_task = asyncio.create_task(current_upstream_ws.recv(), name=f"upstream-{target_host}")

                if client_task_finished:
                    if client_read_task.exception() is not None and not isinstance(client_read_task.exception(), (asyncio.CancelledError,)):
                        error = client_read_task.exception()
                        raise UpstreamConnectionFailure(f"Client read error: {error}") from error
                    data_from_client = client_read_task.result()
                    if not data_from_client:
                        break
                    connection_state.buffer_data(data_from_client)
                    try:
                        await current_upstream_ws.send(data_from_client)
                    except (ConnectionClosed, OSError, Exception) as error:
                        if (
                            current_path == "worker"
                            and not connection_state.connection_active
                            and self.is_fallback_enabled
                        ):
                            try:
                                error_reason = f"worker send failed: {type(error).__name__}"
                                await failover_to_fallback(error_reason)
                                continue
                            except UpstreamConnectionFailure as fallback_exc:
                                raise fallback_exc from error
                        if connection_state.connection_active:
                            break
                        raise UpstreamConnectionFailure(f"Failed to send to upstream: {error}") from error
                    client_read_task = asyncio.create_task(client_reader.read(65536), name=f"client-{target_host}")
        finally:
            for task in (client_read_task, upstream_read_task):
                if not task.done():
                    task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
                except Exception:
                    pass

        return current_upstream_ws

    async def _respond_socks_failure(self, client_writer: asyncio.StreamWriter, error_code: int = 0x01) -> None:
        client_writer.write(b"\x05" + bytes([error_code]) + b"\x00\x01" + b"\x00\x00\x00\x00" + b"\x00\x00")
        await client_writer.drain()

    async def _respond_socks_success(self, client_writer: asyncio.StreamWriter, full_socks_request: bytes) -> None:
        client_writer.write(b"\x05\x00\x00\x01" + b"\x00\x00\x00\x00" + b"\x00\x00")
        await client_writer.drain()

    async def _establish_upstream_connection(
        self, 
        host_for_connect: str, 
        target_host: str, 
        target_port: int
    ) -> Tuple[WebSocketClientProtocol, str]:
        try:
            if self._is_host_in_service_list(target_host.lower()):
                if self.is_fallback_enabled:
                    print(f"{self.service_name}: pre-fallback to relay for {target_host}:{target_port} (hostname matches cf_hostnames)")
                    upstream_ws = await self._establish_fallback_connection(target_host, target_port)
                    return upstream_ws, "relay"
            
            is_service_addr, checked_addr = await asyncio.to_thread(
                determine_if_service_ip,
                target_host,
                self.enable_secure_dns,
                self.secure_dns_timeout,
            )
            if is_service_addr and self.is_fallback_enabled:
                print(f"{self.service_name}: pre-fallback to relay for {target_host}:{target_port} (Target served by Cloudflare IP range)")
                upstream_ws = await self._establish_fallback_connection(target_host, target_port)
                return upstream_ws, "relay"
        except Exception:
            pass

        try:
            upstream_ws = await self._establish_worker_connection(host_for_connect, target_port)
            return upstream_ws, "worker"
        except ServiceMustUseRelay as exc:
            if not self.is_fallback_enabled:
                raise UpstreamConnectionFailure(exc.reason)
            print(f"{self.service_name}: fallback to relay for {target_host}:{target_port} ({exc.reason})")
            upstream_ws = await self._establish_fallback_connection(target_host, target_port)
            return upstream_ws, "relay"

    async def _establish_worker_connection(self, target_host: str, target_port: int) -> WebSocketClientProtocol:
        connection_headers = {}
        if self.api_secret_key:
            connection_headers["Authorization"] = self.api_secret_key

        try:
            upstream_ws = await ws_connect(self.ws_connect_url, extra_headers=connection_headers, max_size=None)
        except Exception as error:
            raise UpstreamConnectionFailure(f"Failed to open worker tunnel: {error}") from error

        try:
            await upstream_ws.send(json.dumps({
                "hostname": target_host,
                "port": target_port,
                "password": self.tunnel_credential
            }))
        except Exception as error:
            with contextlib.suppress(Exception):
                await upstream_ws.close()
            raise UpstreamConnectionFailure("Failed to transmit worker handshake") from error

        ack_message = await self._wait_for_upstream_ack(upstream_ws)
        if ack_message.get("type") == "ready":
            return upstream_ws

        error_detail = ack_message.get("message") or ack_message.get("code") or "Worker rejected connection"
        with contextlib.suppress(Exception):
            await upstream_ws.close()

        if ack_message.get("code") == "cloudflare-blocked":
            raise ServiceMustUseRelay(error_detail)

        raise UpstreamConnectionFailure(error_detail)

    async def _establish_fallback_connection(self, target_host: str, target_port: int) -> WebSocketClientProtocol:
        if not self.is_fallback_enabled or not self.fallback_ws_url:
            raise UpstreamConnectionFailure("Relay not configured")

        connection_headers = {}
        if self.fallback_api_key:
            connection_headers["Authorization"] = self.fallback_api_key

        try:
            upstream_ws = await ws_connect(self.fallback_ws_url, extra_headers=connection_headers, max_size=None)
        except Exception as error:
            raise UpstreamConnectionFailure(f"Failed to open relay tunnel: {error}") from error

        try:
            await upstream_ws.send(json.dumps({
                "hostname": target_host,
                "port": target_port,
                "password": self.fallback_credential
            }))
        except Exception as error:
            with contextlib.suppress(Exception):
                await upstream_ws.close()
            raise UpstreamConnectionFailure("Failed to transmit relay handshake") from error

        ack_message = await self._wait_for_upstream_ack(upstream_ws)
        if ack_message.get("type") == "ready":
            return upstream_ws

        error_detail = ack_message.get("message") or ack_message.get("code") or "Relay rejected connection"
        with contextlib.suppress(Exception):
            await upstream_ws.close()
        raise UpstreamConnectionFailure(error_detail)

    async def _wait_for_upstream_ack(self, upstream_ws: WebSocketClientProtocol) -> Dict:
        try:
            raw_ack = await asyncio.wait_for(upstream_ws.recv(), timeout=self.upstream_ack_timeout)
        except asyncio.TimeoutError as error:
            raise UpstreamConnectionFailure("Timed out waiting for upstream acknowledgement") from error
        except Exception as error:
            raise UpstreamConnectionFailure("Upstream channel closed during handshake") from error

        if isinstance(raw_ack, (bytes, bytearray, memoryview)):
            raise UpstreamConnectionFailure("Unexpected binary response from upstream")

        try:
            ack_payload = json.loads(raw_ack)
        except (TypeError, json.JSONDecodeError) as error:
            raise UpstreamConnectionFailure("Invalid control response from upstream") from error

        if not isinstance(ack_payload, dict):
            raise UpstreamConnectionFailure("Malformed control response from upstream")

        return ack_payload

    def _is_host_in_service_list(self, target_host: str) -> bool:
        if not self.service_host_patterns:
            return False

        for pattern in self.service_host_patterns:
            if target_host == pattern:
                return True
            if pattern.startswith("*.") and target_host.endswith(pattern[1:]):
                return True
        return False


class TunnelGatewayGroup:
    def __init__(self, gateways: List[LocalTunnelGateway]):
        self.gateway_instances = gateways

    def get_status_report(self) -> List[Tuple[str, str, int]]:
        status_list = []
        for gateway in self.gateway_instances:
            if gateway.listen_port is not None:
                status_list.append((gateway.service_name, gateway.listen_host, gateway.listen_port))
        return status_list

    async def shutdown_all(self) -> None:
        await asyncio.gather(*(gateway.stop_listening() for gateway in self.gateway_instances), return_exceptions=True)


class RelayDirector:

    def __init__(self, settings_path: Optional[str] = None):
        self._settings_file_path = None
        self._settings_modified = False
        self.app_settings = self._retrieve_settings(settings_path)
        self.service_defaults = self._finalize_service_defaults(self.app_settings.get("worker", {}))
        self.local_client_defaults = self._finalize_client_defaults(self.app_settings.get("client", {}))
        self.app_settings["worker"] = self.service_defaults
        self.app_settings["client"] = self.local_client_defaults
        self.service_manager = self._initialize_service_manager()
        self.service_cache_file = "orbital-relay_endpoints.json"
        self._check_for_settings_file()

        if self._settings_modified:
            self._save_settings_to_disk()

    def _retrieve_settings(self, settings_path: Optional[str] = None) -> Dict:
        settings_map = {"cloudflare": {}, "worker": {}, "client": {}}

        if settings_path and os.path.exists(settings_path):
            self._settings_file_path = settings_path
            settings_map = self._read_settings_from_file(settings_path, settings_map)

        potential_settings_files = [
            "orbital-relay.json",
            "cloudproxy.json", 
            os.path.expanduser("~/.orbital-relay.json")
        ]

        for settings_file in potential_settings_files:
            if os.path.exists(settings_file):
                if not self._settings_file_path:
                    self._settings_file_path = settings_file
                settings_map = self._read_settings_from_file(settings_file, settings_map)
                break
        
        if not self._settings_file_path:
            self._settings_file_path = settings_path or "orbital-relay.json"

        return settings_map

    def _read_settings_from_file(self, settings_path: str, settings_map: Dict) -> Dict:
        try:
            with open(settings_path, 'r') as file_handle:
                json_settings = json.load(file_handle)

            if "cloudflare" in json_settings:
                settings_map["cloudflare"].update(json_settings["cloudflare"])

            if "worker" in json_settings and isinstance(json_settings["worker"], dict):
                settings_map["worker"].update(json_settings["worker"])

            if "client" in json_settings and isinstance(json_settings["client"], dict):
                settings_map["client"].update(json_settings["client"])
        except (json.JSONDecodeError, IOError) as error:
            print(f"Warning: Could not load config file {settings_path}: {error}")

        return settings_map

    def _initialize_service_manager(self) -> Optional[WorkerServiceManager]:
        service_api_settings = self.app_settings.get("cloudflare", {})
        auth_secret = service_api_settings.get("api_token")
        org_identifier = service_api_settings.get("account_id")

        if auth_secret and org_identifier:
            return WorkerServiceManager(
                auth_secret=auth_secret,
                org_identifier=org_identifier,
                domain_zone_id=service_api_settings.get("zone_id"),
                service_config=self.service_defaults
            )
        return None

    def _check_for_settings_file(self) -> None:
        potential_settings_files = ["orbital-relay.json", os.path.expanduser("~/.orbital-relay.json")]
        settings_file_found = any(os.path.exists(file_path) for file_path in potential_settings_files)

        if not settings_file_found:
            pass

    def _save_settings_to_disk(self) -> None:
        if not self._settings_file_path:
            return

        try:
            with open(self._settings_file_path, 'w') as file_handle:
                json.dump(self.app_settings, file_handle, indent=2)
        except IOError as error:
            print(f"Warning: Could not update config file {self._settings_file_path}: {error}")
        finally:
            self._settings_modified = False

    def _create_secure_token(self, byte_length: int = 24) -> str:
        return secrets.token_urlsafe(byte_length)

    def _finalize_service_defaults(self, input_service_config: Dict) -> Dict:
        final_settings = dict(input_service_config or {})
        was_modified = False

        if "mode" not in final_settings:
            final_settings["mode"] = "http"
            was_modified = True

        if not final_settings.get("socks_password"):
            final_settings["socks_password"] = self._create_secure_token()
            print("Generated worker SOCKS password for this session. Update your config to persist it.")
            was_modified = True

        if "auth_token" not in final_settings:
            final_settings["auth_token"] = ""
            was_modified = True

        if not final_settings.get("compatibility_date"):
            final_settings["compatibility_date"] = "2023-09-04"
            was_modified = True

        compat_options = final_settings.get("compatibility_flags")
        if not isinstance(compat_options, list) or not compat_options:
            final_settings["compatibility_flags"] = ["nodejs_compat"]
            was_modified = True

        if was_modified:
            self._settings_modified = True

        return final_settings

    def _finalize_client_defaults(self, input_client_config: Dict) -> Dict:
        final_settings = dict(input_client_config or {})
        was_modified = False

        if "bind_host" not in final_settings:
            final_settings["bind_host"] = "127.0.0.1"
            was_modified = True

        if "base_port" not in final_settings:
            final_settings["base_port"] = 1080
            was_modified = True

        if "profiles" not in final_settings:
            final_settings["profiles"] = []
            was_modified = True

        if "auto_random_ports" not in final_settings:
            final_settings["auto_random_ports"] = True
            was_modified = True

        if "cf_override_ip" not in final_settings:
            final_settings["cf_override_ip"] = ""
            was_modified = True
            
        if "cf_hostnames" not in final_settings:
            final_settings["cf_hostnames"] = []
            was_modified = True

        if "handshake_timeout" not in final_settings:
            final_settings["handshake_timeout"] = 5.0
            was_modified = True

        if "use_doh" not in final_settings:
            final_settings["use_doh"] = True
            was_modified = True

        if "doh_timeout" not in final_settings:
            final_settings["doh_timeout"] = 5.0
            was_modified = True

        fallback_settings = final_settings.get("relay")
        if not isinstance(fallback_settings, dict):
            final_settings["relay"] = {
                "enabled": False,
                "url": "",
                "auth_token": "",
                "socks_password": ""
            }
            was_modified = True
        else:
            fallback_defaults = {
                "enabled": False,
                "url": "",
                "auth_token": "",
                "socks_password": ""
            }
            for key, value in fallback_defaults.items():
                if key not in fallback_settings:
                    fallback_settings[key] = value
                    was_modified = True

        if was_modified:
            self._settings_modified = True

        return final_settings

    @property
    def is_ready(self) -> bool:
        return self.service_manager is not None

    def _write_service_cache(self, service_list: List[Dict]) -> None:
        try:
            with open(self.service_cache_file, 'w') as file_handle:
                json.dump(service_list, file_handle, indent=2)
        except IOError as error:
            print(f"Warning: Could not save endpoints: {error}")

    def _read_service_cache(self) -> List[Dict]:
        if os.path.exists(self.service_cache_file):
            try:
                with open(self.service_cache_file, 'r') as file_handle:
                    return json.load(file_handle)
            except (json.JSONDecodeError, IOError):
                pass
        return []

    def _update_and_write_service_cache(self, new_services: List[Dict]) -> None:
        if not new_services:
            return

        existing_service_map = {service_record.get("name"): service_record for service_record in self._read_service_cache() if service_record.get("name")}

        for service_record in new_services:
            service_id = service_record.get("name")
            if not service_id:
                continue
            if service_id in existing_service_map:
                existing_service_map[service_id].update(service_record)
            else:
                existing_service_map[service_id] = service_record

        self._write_service_cache(list(existing_service_map.values()))

    def _prepare_service_for_gateway(self, service_record: Dict) -> Dict:
        gateway_config = dict(service_record)
        gateway_config.setdefault("auth_token", self.service_defaults.get("auth_token", ""))
        gateway_config.setdefault("socks_password", self.service_defaults.get("socks_password", ""))
        return gateway_config

    def _get_services_for_gateways(self, max_count: Optional[int] = None) -> List[Dict]:
        all_services = self._read_service_cache()
        if max_count and max_count > 0:
            all_services = all_services[:max_count]
        return [self._prepare_service_for_gateway(service_record) for service_record in all_services]

    def launch_tunnel_gateways(
        self,
        service_list: List[Dict],
        listen_address: Optional[str] = None,
        starting_port: Optional[int] = None,
        use_random_ports: Optional[bool] = None
    ) -> None:
        if not service_list:
            print("No endpoints available to start SOCKS servers.")
            return

        gateway_listen_host = listen_address or self.local_client_defaults.get("bind_host")
        assign_random_ports = self.local_client_defaults.get("auto_random_ports", True) if use_random_ports is None else use_random_ports
        first_port = starting_port if starting_port is not None else self.local_client_defaults.get("base_port")

        gateway_configs = [self._prepare_service_for_gateway(service_record) for service_record in service_list]

        try:
            asyncio.run(self._async_launch_gateways(gateway_configs, gateway_listen_host, first_port, assign_random_ports))
        except KeyboardInterrupt:
            print("\nStopped local SOCKS proxies.")

    # <-- FIX: Changed type hint to Callable
    async def _async_launch_gateways(
        self,
        gateway_configs: List[Dict],
        listen_address: str,
        starting_port: Optional[int],
        use_random_ports: bool,
        test_coro: Optional[Callable] = None
    ) -> None:
        gateway_instances: List[LocalTunnelGateway] = []
        gateway_manager: Optional[TunnelGatewayGroup] = None
        try:
            idx = 0
            while idx < len(gateway_configs):
                config = gateway_configs[idx]
                requested_port: Optional[int]
                if use_random_ports:
                    requested_port = None
                else:
                    first_port = starting_port if starting_port is not None else 0
                    requested_port = first_port + idx

                gateway = LocalTunnelGateway(config, self.service_defaults, self.local_client_defaults, listen_address)
                await gateway.begin_listening(requested_port)
                gateway_instances.append(gateway)
                idx += 1

            gateway_manager = TunnelGatewayGroup(gateway_instances)
            self._display_gateway_summary(gateway_manager)

            try:
                if test_coro:
                    await test_coro(gateway_manager)
                else:
                    await asyncio.Future()
            except asyncio.CancelledError:
                pass
        finally:
            if gateway_manager:
                await gateway_manager.shutdown_all()
            elif gateway_instances:
                await TunnelGatewayGroup(gateway_instances).shutdown_all()

    # <-- MODIFIED: This function now saves to socks_proxies.txt in ip:port:user:pass format -->
    def _display_gateway_summary(self, gateway_manager: TunnelGatewayGroup) -> None:
        print("\nLocal SOCKS proxies:")
        
        proxy_list_for_file = []
        # We need to access the gateway instances to get credentials
        gateway_instances = gateway_manager.gateway_instances
        
        for gateway in gateway_instances:
            if gateway.listen_port is not None:
                listen_host = gateway.listen_host
                listen_port = gateway.listen_port
                service_id = gateway.service_name
                
                # Get credentials from the gateway instance
                # Use "username" for token and "password" for SOCKS pass
                username = gateway.api_secret_key
                password = gateway.tunnel_credential
                
                # Create the two formats
                display_format = f"socks5://{listen_host}:{listen_port}"
                file_format = f"{listen_host}:{listen_port}:{username}:{password}"
                
                print(f"  {service_id}: {display_format}")
                proxy_list_for_file.append(file_format)
        
        print("Press Ctrl+C to stop.\n")

        if proxy_list_for_file:
            filename = "socks_proxies.txt"
            try:
                # Use 'a' (append) mode
                with open(filename, "a") as f:
                    for proxy_line in proxy_list_for_file:
                        f.write(f"{proxy_line}\n")
                print(f"Appended {len(proxy_list_for_file)} local SOCKS proxy/proxies to {filename} in ip:port:user:pass format\n")
            except IOError as e:
                print(f"Warning: Could not write to {filename}: {e}\n")
    # <-- END: Modified logic -->

    def synchronize_service_cache(self) -> List[Dict]:
        if not self.service_manager:
            return []

        try:
            remote_services = self.service_manager.enumerate_all_services()
            local_service_map = {service_record.get("name"): service_record for service_record in self._read_service_cache() if service_record.get("name")}

            combined_list = []
            for service_record in remote_services:
                service_id = service_record.get("name")
                if service_id and service_id in local_service_map:
                    local_data = local_service_map[service_id]
                    merged_record = {**local_data, **service_record}
                    combined_list.append(merged_record)
                else:
                    combined_list.append(service_record)

            self._write_service_cache(combined_list)
            return combined_list
        except DirectorAppError as error:
            print(f"Warning: Could not sync endpoints: {error}")
            return self._read_service_cache()

    # <-- MODIFIED: This function now stops on fatal error 10037 -->
    def provision_new_services(self, quantity: int = 1) -> Dict:
        if not self.service_manager:
            raise DirectorAppError("OrbitalRelay not configured")

        print(f"\nCreating {quantity} OrbitalRelay endpoint{'s' if quantity != 1 else ''}...")

        provisioning_report = {"created": [], "failed": 0}

        idx = 0
        while idx < quantity:
            try:
                new_service = self.service_manager.provision_new_service()
                provisioning_report["created"].append(new_service)
                print(f"  [{idx+1}/{quantity}] {new_service['name']} -> {new_service['url']}")
            except DirectorAppError as error:
                error_str = str(error)
                print(f"  Failed to create endpoint {idx+1}: {error_str}")
                provisioning_report["failed"] += 1
                
                # <-- START: Added logic to stop on fatal error -->
                if '"code": 10037' in error_str or "exceeded the limit" in error_str:
                    print("\nWorker limit reached. Halting further creation attempts.")
                    # Break out of the while loop
                    break
                # <-- END: Added logic -->
            idx += 1

        self._update_and_write_service_cache(provisioning_report["created"])
        self.synchronize_service_cache()

        success_count = len(provisioning_report["created"])
        print(f"\nCreated: {success_count}, Failed: {provisioning_report['failed']}")

        return provisioning_report
    
    # <-- MODIFIED: This function now saves HTTP proxies to http_proxies.txt -->
    def _run_command_create(self, cli_args: argparse.Namespace) -> None:
        original_mode = None
        
        if cli_args.mode and self.service_manager:
            original_mode = self.service_manager.service_parameters.get("mode")
            self.service_manager.service_parameters["mode"] = cli_args.mode
            print(f"Overriding creation mode: now creating '{cli_args.mode}' workers.")

        try:
            quantity = cli_args.count if cli_args.count and cli_args.count > 0 else 1
            provisioning_report = self.provision_new_services(quantity)

            # <-- START: Added logic to save proxy details to file -->
            newly_created_services = provisioning_report.get("created", [])
            if newly_created_services:
                current_mode = (cli_args.mode or self.service_manager.service_parameters.get("mode", "http")).lower()
                
                if current_mode == 'http':
                    filename = "http_proxies.txt"
                    try:
                        with open(filename, "a") as f:
                            for service in newly_created_services:
                                f.write(f"{service['url']}\n")
                        print(f"Appended {len(newly_created_services)} HTTP proxy URL(s) to {filename}")
                    except IOError as e:
                        print(f"Warning: Could not write to {filename}: {e}")
                
                elif current_mode == 'socks':
                    # SOCKS details will be saved when the proxy is *run* (bound)
                    # by the _display_gateway_summary function.
                    print(f"Created {len(newly_created_services)} SOCKS worker(s).")
                    if not cli_args.bind:
                        print(f"Run 'python3 orbital_relay.py socks' to start them and save to socks_proxies.txt")
            # <-- END: Added logic -->

            if cli_args.bind:
                newly_created_services = provisioning_report.get("created", [])
                if newly_created_services:
                    use_random_ports = self.local_client_defaults.get("auto_random_ports", True)
                    if cli_args.start_port is not None:
                        use_random_ports = False
                    self.launch_tunnel_gateways(
                        newly_created_services,
                        listen_address=cli_args.bind,
                        starting_port=cli_args.start_port,
                        use_random_ports=use_random_ports
                    )
        finally:
            if original_mode and self.service_manager:
                self.service_manager.service_parameters["mode"] = original_mode
    # <-- END: Modified function -->

    def display_all_services(self) -> List[Dict]:
        all_services = self.synchronize_service_cache()

        if not all_services:
            print("No OrbitalRelay endpoints found")
            print("Create some with: python3 orbital_relay.py create")
            return []

        print(f"\nOrbitalRelay Endpoints ({len(all_services)} total):")
        print("-" * 80)
        print(f"{'Name':<35} {'URL':<40} {'Status':<8}")
        print("-" * 80)

        for service_record in all_services:
            service_id = service_record.get("name", "unknown")
            service_url = service_record.get("url", "unknown")
            print(f"{service_id:<35} {service_url:<40} {'Active':<8}")

        return all_services

    def _run_command_list(self, cli_args: argparse.Namespace) -> None:
        self.display_all_services()

    def validate_all_http_services(self, destination_url: str = "https://ifconfig.me/ip", http_verb: str = "GET") -> Dict:
        all_services = self._read_service_cache()

        if not all_services:
            print("No proxy endpoints available. Create some first.")
            return {"success": False, "error": "No endpoints available"}

        validation_report = {}
        success_count = 0
        ip_counts: Dict[str, int] = {} # <-- FIX: Initialize IP counter

        print(f"Testing {len(all_services)} OrbitalRelay HTTP endpoint(s) with {destination_url}")

        service_idx = 0
        while service_idx < len(all_services):
            service_record = all_services[service_idx]
            service_id = service_record.get("name", "unknown")
            print(f"\nTesting endpoint: {service_id}")

            retry_limit = 2
            is_successful = False
            test_outcome = None

            retry_num = 0
            while retry_num < retry_limit:
                try:
                    if retry_num > 0:
                        time.sleep(1)
                        print(f"    Retry {retry_num}...")

                    validation_url = f"{service_record['url']}?url={destination_url}"
                    # Use the increased timeout
                    http_resp = requests.request(http_verb, validation_url, timeout=45) # <-- FIX: Increased timeout

                    test_outcome = {
                        "success": http_resp.status_code == 200,
                        "status_code": http_resp.status_code,
                        "response_length": len(http_resp.content),
                        "headers": dict(http_resp.headers)
                    }

                    if http_resp.status_code == 200:
                        is_successful = True
                        print(f"Request successful! Status: {test_outcome['status_code']}")

                        origin_ip = None # <-- FIX: Variable to hold extracted IP
                        try:
                            http_body_text = http_resp.text.strip()
                            if destination_url in ["https://ifconfig.me/ip", "https://httpbin.org/ip"]:
                                if destination_url == "https://httpbin.org/ip":
                                    json_payload = http_resp.json()
                                    if 'origin' in json_payload:
                                        ip_text = json_payload['origin']
                                        if _validate_ip_format(ip_text): # <-- FIX: Validate IP
                                            origin_ip = ip_text
                                        print(f"    Origin IP: {ip_text}")
                                else: # ifconfig.me
                                    if http_body_text and len(http_body_text) < 100:
                                        if _validate_ip_format(http_body_text): # <-- FIX: Validate IP
                                            origin_ip = http_body_text
                                        print(f"    Origin IP: {http_body_text}")
                                    else:
                                        print(f"    Response: {http_body_text[:100]}...")
                            else:
                                print(f"    Response Length: {test_outcome['response_length']} bytes")
                        except Exception as e:
                             # Still print length even if IP extraction fails
                            print(f"    Response Length: {test_outcome['response_length']} bytes")

                        success_count += 1
                        # <-- FIX: Count IP if successfully extracted and validated
                        if origin_ip:
                            ip_counts[origin_ip] = ip_counts.get(origin_ip, 0) + 1
                        # <-- FIX: End of IP counting block
                        break # Exit retry loop on success

                    elif http_resp.status_code == 503:
                        print(f"    Server unavailable (503) - target service may be overloaded")
                        if retry_num < retry_limit - 1:
                            retry_num += 1
                            continue
                    else:
                        print(f"Request failed! Status: {http_resp.status_code}")
                        break # Exit retry loop on definitive failure

                except requests.RequestException as e:
                    if retry_num < retry_limit - 1:
                        print(f"    Connection error, retrying...")
                        retry_num += 1
                        continue
                    else:
                        print(f"Request failed: {e}")
                        test_outcome = {"success": False, "error": str(e)}
                        break # Exit retry loop after last retry fails
                except Exception as e:
                    print(f"Test failed: {e}")
                    test_outcome = {"success": False, "error": str(e)}
                    break # Exit retry loop on unexpected error
                
                # This should only be reached if retrying (status 503 or RequestException)
                retry_num += 1 
            
            validation_report[service_id] = test_outcome if test_outcome else {"success": False, "error": "Unknown error"}
            service_idx += 1

        print(f"\nTest Results:")
        print(f"    Working endpoints: {success_count}/{len(all_services)}")
        if success_count < len(all_services):
            failure_count = len(all_services) - success_count
            print(f"    Failed endpoints: {failure_count} (may be due to target service issues)")
        # <-- FIX: Update final summary print logic
        if ip_counts:
             print(f"    Unique IP addresses: {len(ip_counts)}")
             for ip, count in sorted(ip_counts.items()):
                 print(f"        - {ip} (used by {count} worker{'s' if count > 1 else ''})")
        # <-- FIX: End of summary update

        return validation_report

    def _run_command_test_http(self, cli_args: argparse.Namespace) -> None:
        url_to_test = "https://ifconfig.me/ip" # Default
        method = "GET"
        if cli_args.url:
             url_to_test = cli_args.url
             # Only allow GET for non-default URLs for simplicity unless specified
             if cli_args.method and cli_args.method.upper() != "GET":
                  method = cli_args.method.upper()
             # Warn if testing IP with a non-IP URL
             if url_to_test not in ["https://ifconfig.me/ip", "https://httpbin.org/ip"]:
                 print(f"Warning: Testing with URL '{url_to_test}'. IP address summary will not be shown.")

        self.validate_all_http_services(url_to_test, method)

    # <-- RESTORED: Original curl-based SOCKS test -->
    async def _test_single_socks_proxy(self, service_id: str, host: str, port: int) -> Tuple[str, str]:
        cmd = "curl"
        # Increased connect timeout for curl
        args = ["--socks5", f"{host}:{port}", "https://ifconfig.me/ip", "--connect-timeout", "15", "-s"] # <-- FIX: Increased timeout
        
        try:
            proc = await asyncio.create_subprocess_exec(
                cmd,
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            # Increased overall wait time for the process
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=20) # <-- FIX: Increased timeout
            
            if proc.returncode == 0:
                ip = stdout.decode().strip()
                if _validate_ip_format(ip):
                    return (service_id, ip)
                else:
                    # Try to capture more of the error if it's not a valid IP
                    error_detail = ip[:100] # Limit length
                    return (service_id, f"Invalid IP response: {error_detail}")
            else:
                error = stderr.decode().strip() or "Process failed with no error message"
                # Try to capture more of the curl error
                return (service_id, f"Curl error: {error[:100]}") # Limit length
                
        except asyncio.TimeoutError:
            return (service_id, "Test timed out")
        except Exception as e:
            return (service_id, str(e))

    def _run_command_test_socks(self, cli_args: argparse.Namespace) -> None:
        services_to_start = self._get_services_for_gateways()
        if not services_to_start:
            print("No proxy endpoints available. Create some first.")
            return

        listen_address = self.local_client_defaults.get("bind_host")
        use_random_ports = True 

        async def run_all_tests(gateway_manager: TunnelGatewayGroup):
            print("\n🔬 Starting SOCKS proxy tests...")
            test_tasks = []
            status_report = gateway_manager.get_status_report()
            
            for service_id, listen_host, listen_port in status_report:
                task = asyncio.create_task(
                    self._test_single_socks_proxy(service_id, listen_host, listen_port)
                )
                test_tasks.append(task)
            
            results = await asyncio.gather(*test_tasks, return_exceptions=True)
            
            print("\n" + "=" * 30)
            print("SOCKS Test Results:")
            print("=" * 30)
            
            success_count = 0
            fail_count = 0
            ip_counts: Dict[str, int] = {} 
            
            for result in results:
                if isinstance(result, tuple) and len(result) == 2:
                    service_id, ip_or_error = result
                    if _validate_ip_format(ip_or_error):
                        print(f"  SUCCESS: {service_id} -> IP: {ip_or_error}")
                        success_count += 1
                        ip_counts[ip_or_error] = ip_counts.get(ip_or_error, 0) + 1 
                    else:
                        print(f"  FAILED:  {service_id} -> Error: {ip_or_error}")
                        fail_count += 1
                elif isinstance(result, Exception): 
                    print(f"  FAILED:  Internal testing error: {result}")
                    fail_count += 1
                else: 
                    print(f"  FAILED:  Unknown error format: {result}")
                    fail_count += 1

            print("\n" + "-" * 30)
            print(f"Summary: {success_count} working, {fail_count} failed.")
            if ip_counts:
                 print(f"    Unique IP addresses: {len(ip_counts)}")
                 for ip, count in sorted(ip_counts.items()):
                     print(f"        - {ip} (used by {count} worker{'s' if count > 1 else ''})")
            print("Shutting down test proxies..." + "\n")

        try:
            asyncio.run(self._async_launch_gateways(
                services_to_start,
                listen_address,
                starting_port=None,
                use_random_ports=use_random_ports,
                test_coro=run_all_tests
            ))
        except KeyboardInterrupt:
            print("\nTests cancelled.")

    def _run_command_socks(self, cli_args: argparse.Namespace) -> None:
        max_count = cli_args.count if cli_args.count and cli_args.count > 0 else None
        services_to_start = self._get_services_for_gateways(max_count)

        if not services_to_start:
            print("No proxy endpoints available. Create some first.")
            return

        use_random_ports = self.local_client_defaults.get("auto_random_ports", True)
        if cli_args.start_port is not None:
            use_random_ports = False

        self.launch_tunnel_gateways(
            services_to_start,
            listen_address=cli_args.bind,
            starting_port=cli_args.start_port,
            use_random_ports=use_random_ports
        )

    def deprovision_all_services(self) -> None:
        if not self.service_manager:
            raise DirectorAppError("OrbitalRelay not configured")

        print(f"\nCleaning up OrbitalRelay endpoints...")

        try:
            self.service_manager.deprovision_all_services()
        except DirectorAppError as error:
            print(f"Failed to cleanup: {error}")

        if os.path.exists(self.service_cache_file):
            try:
                os.remove(self.service_cache_file)
            except OSError:
                pass

    def _run_command_cleanup(self, cli_args: argparse.Namespace) -> None:
        user_confirmation = input("Delete ALL OrbitalRelay endpoints? (y/N): ")
        if user_confirmation.lower() == 'y':
            self.deprovision_all_services()
        else:
            print("Cleanup cancelled.")


def _validate_ip_format(address_str: str) -> bool:
    if not address_str or not isinstance(address_str, str):
        return False
    try:
        octets = address_str.split('.')
        if len(octets) != 4:
            return False
        
        i = 0
        while i < len(octets):
            octet_str = octets[i]
            octet_val = int(octet_str)
            if octet_val < 0 or octet_val > 255:
                return False
            i += 1
        return True
    except (ValueError, AttributeError):
        return False


def fetch_ipv4_from_doh(domain_name: str, wait_limit: float = 5.0, check_ledger: bool = True) -> Optional[str]:
    if check_ledger:
        ledger_entry = g_resolution_ledger.get(domain_name)
        if ledger_entry:
            addr, recorded_time = ledger_entry
            if time.time() - recorded_time < G_RESOLUTION_EXPIRATION_SEC:
                return addr
    
    try:
        resolver_endpoint = f"https://cloudflare-dns.com/dns-query?name={domain_name}&type=A"
        headers = {"Accept": "application/dns-json"}
        
        http_resp = requests.get(resolver_endpoint, headers=headers, timeout=wait_limit)
        http_resp.raise_for_status()
        
        json_payload = http_resp.json()
        
        if json_payload.get("Status") == 0 and json_payload.get("Answer"):
            for dns_record in json_payload["Answer"]:
                record_addr = dns_record.get("data", "")
                if record_addr and _validate_ip_format(record_addr):
                    if check_ledger:
                        g_resolution_ledger[domain_name] = (record_addr, time.time())
                    return record_addr
            
        return None
        
    except Exception as e:
        print(f"[Debug] DoH resolution for {domain_name} failed: {e}")
        return None


def _check_address_in_service_ranges(address_obj: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]) -> bool:
    service_ipv4_nets = (
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
        "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
        "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
        "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    )

    service_ipv6_nets = (
        "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
        "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29",
        "2c0f:f248::/32",
    )
    
    if not isinstance(address_obj, ipaddress.IPv4Address):
        if not hasattr(_check_address_in_service_ranges, '_cached_ipv6_cidrs'):
            _check_address_in_service_ranges._cached_ipv6_cidrs = [
                ipaddress.ip_network(cidr) for cidr in service_ipv6_nets
            ]
        return any(address_obj in cidr_block for cidr_block in _check_address_in_service_ranges._cached_ipv6_cidrs)
    else:
        if not hasattr(_check_address_in_service_ranges, '_cached_ipv4_cidrs'):
            _check_address_in_service_ranges._cached_ipv4_cidrs = [
                ipaddress.ip_network(cidr) for cidr in service_ipv4_nets
            ]
        return any(address_obj in cidr_block for cidr_block in _check_address_in_service_ranges._cached_ipv4_cidrs)


def determine_if_service_ip(host_or_ip: str, use_secure_dns: bool = True, secure_dns_timeout: float = 5.0) -> Tuple[bool, str]:
    try:
        parsed_address = ipaddress.ip_address(host_or_ip)
        is_service_ip = _check_address_in_service_ranges(parsed_address)
        return (is_service_ip, host_or_ip)
    except ValueError:
        pass
    
    if use_secure_dns:
        looked_up_addr = fetch_ipv4_from_doh(host_or_ip, wait_limit=secure_dns_timeout)
        if looked_up_addr:
            try:
                parsed_address = ipaddress.ip_address(looked_up_addr)
                is_service_ip = _check_address_in_service_ranges(parsed_address)
                return (is_service_ip, looked_up_addr)
            except ValueError:
                return (False, looked_up_addr)
        else:
            return (False, host_or_ip)
    else:
        try:
            looked_up_addr = socket.gethostbyname(host_or_ip)
            parsed_address = ipaddress.ip_address(looked_up_addr)
            is_service_ip = _check_address_in_service_ranges(parsed_address)
            return (is_service_ip, looked_up_addr)
        except (socket.gaierror, socket.herror, ValueError):
            return (False, host_or_ip)


# <-- FIX: Renamed function and added new prompts for mode/relay
def run_default_setup() -> bool:
    print("--- Default Setup ---")
    print("You will need your Cloudflare Account ID and an API Token.")
    print("1. Go to https://dash.cloudflare.com/profile/api-tokens")
    print("2. Click 'Create Token' and use the 'Edit Cloudflare Workers' template.")
    print("3. Set 'Account Resources' and 'Zone Resources' to 'All'.")
    print("4. Copy the generated token and your Account ID (from the main dashboard).")
    print()

    auth_secret = getpass.getpass("Enter your Cloudflare API token: ").strip()
    if not auth_secret:
        print("API token is required")
        return False

    org_identifier = input("Enter your Cloudflare Account ID: ").strip()
    if not org_identifier:
        print("Account ID is required")
        return False

    mode = ""
    while mode not in ["http", "socks"]:
        mode = input("Enter default worker mode (http/socks): ").strip().lower()
        if mode not in ["http", "socks"]:
            print("Invalid mode. Please enter 'http' or 'socks'.")
            
    relay_url = input("Enter relay URL (optional, e.g., https://my-relay.workers.dev): ").strip()

    settings_map = {
        "cloudflare": {
            "api_token": auth_secret,
            "account_id": org_identifier,
            "zone_id": ""
        },
        "worker": {
            "mode": mode,
            "auth_token": "",
            "compatibility_date": "2023-09-04",
            "compatibility_flags": ["nodejs_compat"]
        },
        "client": {
            "bind_host": "127.0.0.1",
            "base_port": 1080,
            "auto_random_ports": True,
            "use_doh": True,
            "relay": {
                "enabled": bool(relay_url),
                "url": relay_url,
                "auth_token": "",
                "socks_password": ""
            }
        }
    }

    settings_path = "orbital-relay.json"
    try:
        with open(settings_path, 'w') as file_handle:
            json.dump(settings_map, file_handle, indent=2)
        print(f"\nConfiguration saved to {settings_path}")
        print("OrbitalRelay is now configured and ready to use!")
        return True
    except IOError as error:
        print(f"Error saving configuration: {error}")
        return False

# <-- FIX: Added new function for advanced setup
def run_advanced_setup() -> bool:
    print("--- Advanced Setup ---")
    settings_path = "orbital-relay.json"
    
    print(f"Loading or creating '{settings_path}' with defaults...")
    try:
        # This will load orbital-relay.json, apply defaults, and save if modified
        temp_director = RelayDirector(settings_path=settings_path)
        
        # Now save it back, ensuring it's complete before editing
        if temp_director._settings_modified:
            temp_director._save_settings_to_disk()
            
        settings_path = temp_director._settings_file_path
        print(f"Opening '{settings_path}' in your default text editor...")
        print("Please save and close the editor when you are done.")
        
        if os.name == 'nt':
            editor = 'notepad'
        else:
            editor = os.environ.get('EDITOR', 'nano') # 'nano' is a friendlier default than 'vi'
        
        try:
            subprocess.run([editor, settings_path], check=True)
        except FileNotFoundError:
            print(f"\nError: Editor '{editor}' not found.")
            print(f"Please edit '{settings_path}' manually.")
            return False
        except subprocess.CalledProcessError as e:
            print(f"\nEditor closed with an error: {e}.")
            print(f"Please check '{settings_path}' manually.")
            return False
        except Exception as e:
            print(f"\nFailed to open editor: {e}")
            print(f"Please edit '{settings_path}' manually.")
            return False

        print(f"Validating '{settings_path}' after edit...")
        try:
            with open(settings_path, 'r') as f:
                json.load(f) # Just try to parse it
            print("Configuration saved successfully.")
            return True
        except json.JSONDecodeError as e:
            print(f"\nError: Invalid JSON in '{settings_path}'.")
            print(f"Details: {e}")
            print("Your changes were NOT saved correctly. Please fix the file manually.")
            return False
            
    except Exception as e:
        print(f"An error occurred during advanced setup: {e}")
        print(f"Please check '{settings_path}' manually.")
        return False


def build_cli_parser() -> argparse.ArgumentParser:
    arg_parser = argparse.ArgumentParser(description="OrbitalRelay - Simple URL Redirection via Cloudflare Workers")

    arg_parser.add_argument("command", nargs='?',
                            choices=["create", "list", "test_http", "test_socks", "cleanup", "help", "config", "socks"],
                            help="Command to execute")

    arg_parser.add_argument("--url", help="Target URL (for test_http)")
    arg_parser.add_argument("--method", default="GET", help="HTTP method (for test_http)")
    arg_parser.add_argument("--mode", choices=["http", "socks"], help="Worker mode to create (overrides config)")
    arg_parser.add_argument("--count", type=int, help="Number of proxies to create or use")
    arg_parser.add_argument("--config", help="Configuration file path")
    arg_parser.add_argument("--bind", help="Bind address for local SOCKS proxies")
    arg_parser.add_argument("--start-port", type=int, help="Starting port for local SOCKS proxies")

    return arg_parser


def display_basic_help() -> None:
    print("OrbitalRelay - Simple URL Redirection via Cloudflare Workers")
    print("\nUsage: python3 orbital_relay.py <command> [options]")
    print("\nCommands:")
    print("  config     Show configuration help and setup")
    print("  create     Create new proxy endpoints")
    print("  list       List all proxy endpoints")
    print("  test_http  Test HTTP proxy endpoints and show IP addresses")
    print("  test_socks Test SOCKS proxy endpoints (uses curl)")
    print("  socks      Start local SOCKS proxy server(s)")
    print("  cleanup    Delete all proxy endpoints")
    print("  help       Show detailed help")
    print("\nExamples:")
    print("  python3 orbital_relay.py config")
    print("  python3 orbital_relay.py create --count 5 --mode socks")
    print("  python3 orbital_relay.py test_http")
    print("  python3 orbital_relay.py test_socks")
    print("  python3 orbital_relay.py socks --bind 127.0.0.1")


def display_setup_guide() -> None:
    print("OrbitalRelay Configuration")
    print("=" * 40)

    potential_settings_files = ["orbital-relay.json", os.path.expanduser("~/.orbital-relay.json")]
    good_config_exists = False
    found_settings_files = []

    for settings_path in potential_settings_files:
        if os.path.exists(settings_path):
            found_settings_files.append(settings_path)
            try:
                with open(settings_path, 'r') as file_handle:
                    json_settings = json.load(file_handle)
                    service_api_settings = json_settings.get("cloudflare", {})
                    auth_secret = service_api_settings.get("api_token", "").strip()
                    org_identifier = service_api_settings.get("account_id", "").strip()

                    if (auth_secret and org_identifier and
                        auth_secret not in ["", "your_cloudflare_api_token_here"] and
                        org_identifier not in ["", "your_cloudflare_account_id_here"] and
                        len(auth_secret) > 10 and len(org_identifier) > 10):
                        good_config_exists = True
                        break
            except (json.JSONDecodeError, IOError):
                continue

    if good_config_exists:
        print(f"\nOrbitalRelay appears to be configured.")
        print("Configuration files found:")
        for settings_path in found_settings_files:
            print(f"  - {settings_path}")
        print()
        user_decision = input("Do you want to reconfigure? (y/n): ").lower().strip()
        if user_decision != 'y':
            print("Configuration cancelled.")
            return
            
    elif found_settings_files:
        print(f"\nConfiguration files exist but may contain placeholder values:")
        for settings_path in found_settings_files:
            print(f"  - {settings_path}")
        print()
    else:
        print("\nNo configuration file found.")

    print("\nSelect configuration mode:")
    print("  (1) Default Setup: Configure key options (Account, Mode, Relay URL)")
    print("  (2) Advanced Setup: Open 'orbital-relay.json' in a text editor for full control")
    print("  (q) Quit")
    
    choice = ""
    while choice not in ['1', '2', 'q']:
        choice = input("Enter your choice (1, 2, or q): ").strip().lower()

    if choice == '1':
        print("\nStarting Default Setup...")
        if run_default_setup():
            print("\nYou can now use OrbitalRelay:")
            print("  python3 orbital_relay.py create --count 2")
            print("  python3 orbital_relay.py test_http")
        else:
            print("\nConfiguration failed. Please try again.")
    elif choice == '2':
        print("\nStarting Advanced Setup...")
        run_advanced_setup()
    else:
        print("Configuration cancelled.")


def display_extended_help() -> None:
    print("OrbitalRelay - Detailed Help")
    print("=" * 30)
    print("\nOrbitalRelay provides simple URL redirection through Cloudflare Workers.")
    print("All traffic sent to your OrbitalRelay endpoints will be redirected to")
    print("the target URL you specify, supporting all HTTP methods.")
    print("\nFeatures:")
    print("- Support for all HTTP methods (GET, POST, PUT, DELETE, etc.)")
    print("- Automatic CORS headers")
    print("- IP masking through Cloudflare's global network")
    print("- Simple URL-based redirection")
    print("- Free tier: 100,000 requests/day")


def execute_application():
    try:
        arg_parser = build_cli_parser()
        cli_args = arg_parser.parse_args()

        if not cli_args.command:
            display_basic_help()
            return

        if cli_args.command == "config":
            display_setup_guide()
            return

        if cli_args.command == "help":
            display_extended_help()
            return

        try:
            director_app = RelayDirector(settings_path=cli_args.config)
        except Exception as error:
            print(f"Configuration error: {error}")
            return

        if not director_app.is_ready:
            print("OrbitalRelay not configured. Use 'python3 orbital_relay.py config' for setup.")
            return

        try:
            command_actions = {
                "create": director_app._run_command_create,
                "list": director_app._run_command_list,
                "test_http": director_app._run_command_test_http,
                "test_socks": director_app._run_command_test_socks,
                "socks": director_app._run_command_socks,
                "cleanup": director_app._run_command_cleanup,
            }
            
            action_func = command_actions.get(cli_args.command)
            if action_func:
                action_func(cli_args)
            
        except DirectorAppError as error:
            print(f"Error: {error}")
        except Exception as error:
            print(f"Unexpected error: {error}")

    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        return


if __name__ == "__main__":
    execute_application()
