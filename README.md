# OrbitalRelay 🚀

OrbitalRelay utilizes Cloudflare Workers to create dynamic proxy endpoints, designed for reliability and resilience. It supports deploying both simple HTTP redirection workers and robust SOCKS5 workers simultaneously. The SOCKS5 mode includes an intelligent fallback mechanism, automatically routing traffic through a secondary relay server (deployable on free-tier services like Render) when direct connections via Cloudflare encounter blocks. This ensures high availability while operating entirely within free service limits.

## ✨ Features

- **Dual Modes**: Deploy `http` or `socks` workers using the `create --mode <mode>` flag.
- **SOCKS5 Proxy Mode**: Provides a standard SOCKS5 interface locally. Offers enhanced resilience through an automatic fallback relay.
- **Automatic Fallback Relay (SOCKS5 Mode)**: Seamlessly switches to a secondary relay server if a Cloudflare Worker fails to connect.
- **Intelligent Configuration**: The `config` command now offers:
  - A **Default Setup** for a quick, guided experience.
  - An **Advanced Setup** that opens your `orbital-relay.json` in your default text editor (nano, notepad, etc.).
- **Proxy List Export**:
  - `create --mode http` automatically appends new proxy URLs to `http_proxies.txt`.
  - The `socks` command automatically appends local proxy details (in `ip:port:user:pass` format) to `socks_proxies.txt`.
- **Separated Testing**:
  - `test_http`: Tests deployed workers via HTTP and provides a summary of unique egress IPs.
  - `test_socks`: Automatically spins up, tests deployed workers via SOCKS using curl, provides a summary, and tears them down.
- **Rate Limit Handling**: Automatically stops the `create` command if it detects a Cloudflare "Worker limit reached" error (code 10037).
- **IP Masking**: Hides your origin IP behind Cloudflare or your relay's IP. Note: This does not guarantee unique IPs for each worker.

## Use Cases & Target Audience

This tool is ideal for security researchers, penetration testers, and bug bounty hunters:

- **Bypassing CDN/WAF Blocks**: Use SOCKS5 mode to automatically failover to your relay when a target blocks Cloudflare's IPs.
- **Tool Integration**: Feed `socks_proxies.txt` into proxychains on Kali/Parrot, or configure Burp Suite to use a local port for resilient scanning.
- **HTTP Proxying**: Use `http_proxies.txt` as a list of simple redirectors for scripts.

## Components

- `orbital_relay.py`: The main CLI script.
- `orbital_relay_server.py`: The fallback relay server (for SOCKS5 mode).
- `orbital-relay.json`: Main configuration file.
- `orbital-relay_endpoints.json`: Auto-generated cache of all deployed workers. Crucially, this file does not store the mode (http/socks), which is why the `socks`, `test_http`, and `test_socks` commands cannot filter by worker type.
- `requirements.txt`: Python dependencies (websockets, requests).
- `runtime.txt`: (Optional) Specifies `python-3.11.6` for Render.
- `http_proxies.txt`: (Auto-generated) Stores HTTP worker URLs.
- `socks_proxies.txt`: (Auto-generated) Stores local SOCKS proxy details (`ip:port:user:pass`).

## 🛠️ Setup Workflow (SOCKS5 Mode Recommended)

### 1. Dependencies

Clone the repository and install requirements:

```bash
git clone https://github.com/your-username/orbital-relay.git
cd orbital-relay
pip3 install -r requirements.txt
```

*(Ensure `requirements.txt` includes `websockets` and `requests`)*

### 2. Cloudflare API Credentials

1. Log in to Cloudflare > **My Profile** > **API Tokens**.
2. Click **Create Token** > **Edit Cloudflare Workers** template.
3. Set **Account Resources** to your account.
4. Set **Zone Resources** to "All zones".
5. **Create Token** and copy the **API Token**.
6. Go to the main dashboard to copy your **Account ID**.

### 3. Configure OrbitalRelay

Run the interactive configuration command:

```bash
python3 orbital_relay.py config
```

You will be given two options:

1. **Default Setup**: A guided prompt that asks for your API Token, Account ID, default Mode (`http` or `socks`), and optional Relay URL. This is the fastest way to get started.
2. **Advanced Setup**: This will automatically open your `orbital-relay.json` file in your default text editor (like nano) for full customization.

### 4. Deploy the Fallback Relay (SOCKS5 Mode)

**This step is only required if you use SOCKS5 mode.**

1. **Run Initial Config**: Run `python3 orbital_relay.py config` and choose **Advanced Setup** to generate a default `orbital-relay.json` file.

2. **Edit Local JSON**: In `orbital-relay.json`:
   - Set `"mode": "socks"` in the `"worker"` section.
   - In the `"relay"` section, invent secure, random passwords for `auth_token` and `socks_password`.

3. **Deploy to Render**: Deploy `orbital_relay_server.py` to Render.
   - Create a new **Web Service** on Render, connected to your GitHub repo.
   - **Build Command**: `pip3 install -r requirements.txt`
   - **Start Command**: `python3 orbital_relay_server.py`
   - Set these **Environment Variables** in Render, using the exact values from Step 2:
     - `ORBITAL_RELAY_TOKEN`: (The `auth_token` value from your JSON)
     - `ORBITAL_RELAY_PASSWORD`: (The `socks_password` value from your JSON)
     - `PYTHON_VERSION`: `3.11.6` (or as specified in `runtime.txt`)

4. **Update Local JSON (with URL)**:
   - Once Render is live, copy its URL (e.g., `https://my-relay.onrender.com`).
   - Paste it into `orbital-relay.json` as the `"url"` value, using `wss://` (e.g., `wss://my-relay.onrender.com`).
   - Set `"enabled": true` in the `"relay"` section.

5. **Keep Alive (Important!)**: Render's free services sleep. Use a free service like **UptimeRobot** to send an HTTP(s) ping to your Render URL (e.g., `https://my-relay.onrender.com`) every 5-10 minutes to keep it awake.

## ⚙️ Configuration File (orbital-relay.json)

Here is a full example configuration for SOCKS5 mode with a relay:

```json
{
  "cloudflare": {
    "api_token": "YOUR_CLOUDFLARE_API_TOKEN",
    "account_id": "YOUR_CLOUDFLARE_ACCOUNT_ID"
  },
  "worker": {
    "mode": "socks",
    "socks_password": "GENERATED_OR_SET_PASSWORD_FOR_WORKER",
    "auth_token": "",
    "compatibility_date": "2023-09-04",
    "compatibility_flags": [
      "nodejs_compat"
    ]
  },
  "client": {
    "bind_host": "127.0.0.1",
    "base_port": 1080,
    "auto_random_ports": true,
    "cf_hostnames": [
      "*.workers.dev"
    ],
    "handshake_timeout": 5.0,
    "use_doh": true,
    "doh_timeout": 5.0,
    "relay": {
      "enabled": true,
      "url": "wss://your-relay-server.onrender.com",
      "auth_token": "secret_token_for_relay",
      "socks_password": "password_for_relay"
    }
  }
}
```

## 🚀 Usage

### 1. Deploy Cloudflare Workers

Run the `create` command. Use the `--mode` flag (`--mode socks` or `--mode http`) to force a specific worker type, irrespective of the default mode set in your `orbital-relay.json` file.

```bash
# Deploy 5 SOCKS workers, forcing SOCKS mode
python3 orbital_relay.py create --count 5 --mode socks

# Deploy 2 HTTP workers, forcing HTTP mode
python3 orbital_relay.py create --count 2 --mode http
```

- Creating HTTP workers will save their URLs to `http_proxies.txt`.
- Creating SOCKS workers just provisions them. They are saved to `socks_proxies.txt` when you run them.

### 2. Running the Proxy

**If you deployed SOCKS workers**: Run the `socks` command to start the local SOCKS5 client.

> ⚠️ **Warning**: This command starts a proxy for every worker in your `orbital-relay_endpoints.json` file. Proxies pointing to HTTP workers will fail to connect. You must identify the correct ports for your SOCKS workers from the output.

```bash
python3 orbital_relay.py socks
```

**Output**:
```
Local SOCKS proxies:
  orbital-relay-SOCKS-WORKER-1: socks5://127.0.0.1:43327
  orbital-relay-HTTP-WORKER-1: socks5://127.0.0.1:37307  <-- THIS ONE WILL NOT WORK
  orbital-relay-SOCKS-WORKER-2: socks5://127.0.0.1:38791
  ...
Press Ctrl+C to stop.
Appended 3 local SOCKS proxy/proxies to socks_proxies.txt in ip:port:user:pass format
```

**If you deployed HTTP workers**: The workers are live on Cloudflare. You don't run a local client. Use the URLs from `http_proxies.txt`. HTTP workers are redirectors, not standard HTTP proxies.

```bash
# Example using curl with an HTTP worker (Query Parameter Method)
curl "https://<http-worker-url>/?url=https://ifconfig.me/ip"

# Example using curl with an HTTP worker (Header Method)
curl -H "X-Target-URL: https://ifconfig.me/ip" "https://<http-worker-url>/"
```

## 📋 Other Commands

**list**: Show all deployed Cloudflare Worker endpoints.

```bash
python3 orbital_relay.py list
```

**test_http**: ⚠️ Warning: This command tests all deployed workers via HTTP. It will fail for SOCKS workers.

```bash
python3 orbital_relay.py test_http
```

**test_socks**: ⚠️ Warning: This command tests all deployed workers via SOCKS. It will fail for HTTP workers. (Requires curl).

```bash
python3 orbital_relay.py test_socks
```

**cleanup**: Delete ALL OrbitalRelay workers from Cloudflare and clear the local endpoint cache.

```bash
python3 orbital_relay.py cleanup
```

## 💡 How It Works

### HTTP Mode (Redirection)

This diagram shows the clear separation between your local machine, the Cloudflare network, and the final target.

```
+------------------------+                +-------------------------+                +-----------------+
|     YOUR MACHINE       |                |   CLOUDFLARE NETWORK    |                |   TARGET SITE   |
|                        |                |                         |                |                 |
|  [ Your Tool (curl) ]  |  1. Request    |   [ HTTP Worker Script ]|                |                 |
|                        |  (?url=...)    |                         |  2. New Request|                 |
|                        +--------------->+                         +--------------->+ [ example.com ] |
|                        |                |                         |                |                 |
|                        |  4. Final      |                         |  3. Response   |                 |
|                        |  Response      |                         |                |                 |
|                        <---------------+                         <---------------+                 |
|                        |                |                         |                |                 |
+------------------------+                +-------------------------+                +-----------------+
```

### SOCKS5 Mode (with Fallback)

This diagram shows the two distinct paths: the primary attempt through Cloudflare (PATH A) and the automatic fallback to the relay server (PATH B).

```
+------------------------------------------+
|              YOUR MACHINE                |
|                                          |
|  [ App (Burp, Browser) ]                 |
|           |                              |
|           V SOCKS5 (127.0.0.1:<port>)    |
|           |                              |
|  [ Local SOCKS Client (orbital_relay) ]  |
|           |                              |
+-----------+------------------------------+
            |
            | 1. Tries Primary Path (WebSocket)
            |
+-----------V------------------------------+                +-------------------+
|            CLOUDFLARE NETWORK            |                |                   |
|                                          | 2. TCP Connect |                   |
|          [ SOCKS Worker Script ]         +--------------->+   TARGET SITE     |
|                                          |                |   (e.g., IP:443)  |
|                                          |                |                   |
+------------------------------------------+                +-------------------+
  |
  |
  +--- PATH A (Success): Data flows: [App] <-> [Client] <-> [CF Worker] <-> [Target]
  |
  |
  +--- PATH B (Failure ❌):
       1. [CF Worker] -> [Target] is blocked.
       2. [Client] detects the error.
       3. [Client] initiates new WebSocket connection to Fallback.
            |
            |
+-----------V------------------------------+                +-------------------+
|        FALLBACK SERVER (Render)          |                |                   |
|                                          | 4. TCP Connect |                   |
|      [ Fallback Relay Script ]           +--------------->+   TARGET SITE     |
|                                          |                |   (e.g., IP:443)  |
|                                          |                |                   |
+------------------------------------------+                +-------------------+
            |
            |
            +--- Data flows: [App] <-> [Client] <-> [Fallback Relay] <-> [Target]
```

## ⚠️ Disclaimer

This tool is intended for legitimate security research, penetration testing, and bug bounty activities only. Users are responsible for ensuring their usage complies with all applicable laws and regulations.
