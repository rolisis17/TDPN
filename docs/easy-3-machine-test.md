# Easy Installer + 3-Machine Test

This path is for fast manual testing with minimal setup.

## 1) Install the easy launcher

From repo root:

```bash
./scripts/install_easy_mode.sh
```

This checks and reports dependencies:
- `docker`
- `docker compose` plugin
- `curl`
- `g++`

Then it builds:
- `bin/privacynode-easy`

## 2) Interactive mode (C++ launcher)

```bash
./bin/privacynode-easy
```

Menu options:
- dependency check
- server stack start/update
- client test against remote server(s)
- server status/logs/down
- built-in 3-machine checklist
- built-in 3-machine validation runner

## 3) Non-interactive mode (script backend)

All commands below run from repo root.

### Machine A (server)

```bash
./scripts/easy_node.sh server-up \
  --public-host A_PUBLIC_IP_OR_DNS
```

### Machine B (server + federated with A)

```bash
./scripts/easy_node.sh server-up \
  --public-host B_PUBLIC_IP_OR_DNS \
  --peer-directories http://A_PUBLIC_IP_OR_DNS:8081
```

Optional on Machine A to federate both ways:

```bash
./scripts/easy_node.sh server-up \
  --public-host A_PUBLIC_IP_OR_DNS \
  --peer-directories http://B_PUBLIC_IP_OR_DNS:8081
```

### Machine C (client)

```bash
./scripts/easy_node.sh client-test \
  --directory-urls http://A_PUBLIC_IP_OR_DNS:8081,http://B_PUBLIC_IP_OR_DNS:8081 \
  --issuer-url http://A_PUBLIC_IP_OR_DNS:8082 \
  --entry-url http://A_PUBLIC_IP_OR_DNS:8083 \
  --exit-url http://A_PUBLIC_IP_OR_DNS:8084 \
  --min-sources 2
```

Automated validation (recommended on machine C):

```bash
./scripts/easy_node.sh three-machine-validate \
  --directory-a http://A_PUBLIC_IP_OR_DNS:8081 \
  --directory-b http://B_PUBLIC_IP_OR_DNS:8081 \
  --issuer-url http://A_PUBLIC_IP_OR_DNS:8082 \
  --entry-url http://A_PUBLIC_IP_OR_DNS:8083 \
  --exit-url http://A_PUBLIC_IP_OR_DNS:8084 \
  --min-sources 2 \
  --min-operators 2
```

This runs:
- endpoint health checks (`directory`, `issuer`, `entry`, `exit`)
- federation operator-floor check on both directories
- client path bootstrap validation with both directory sources

Role-specific automated checks (recommended before full C run):

Machine A:

```bash
./scripts/easy_node.sh machine-a-test --public-host A_PUBLIC_IP_OR_DNS
```

Machine B:

```bash
./scripts/easy_node.sh machine-b-test \
  --peer-directory-a http://A_PUBLIC_IP_OR_DNS:8081 \
  --public-host B_PUBLIC_IP_OR_DNS
```

Machine C:

```bash
./scripts/easy_node.sh machine-c-test \
  --directory-a http://A_PUBLIC_IP_OR_DNS:8081 \
  --directory-b http://B_PUBLIC_IP_OR_DNS:8081 \
  --issuer-url http://A_PUBLIC_IP_OR_DNS:8082 \
  --entry-url http://A_PUBLIC_IP_OR_DNS:8083 \
  --exit-url http://A_PUBLIC_IP_OR_DNS:8084
```

Each command prints (and can store) a test report file to share for debugging.

Success signal:
- output contains `client selected entry=`

Important:
- on machine C, do not use `127.0.0.1` / `localhost` for A/B URLs; use reachable IP/DNS of machine A/B.

## 4) Ports to open on server machines

- TCP: `8081`, `8082`, `8083`, `8084`
- UDP: `51820`, `51821`

## 5) Useful operations

Server status:

```bash
./scripts/easy_node.sh server-status
```

Server logs:

```bash
./scripts/easy_node.sh server-logs
```

Server stop:

```bash
./scripts/easy_node.sh server-down
```
