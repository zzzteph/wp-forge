"""Sandboxed dynamic-verification helpers.

The finding-verifier subagent uses these to actually run the target app and
prove a vulnerability is reachable (not just present in source). Everything is
namespaced under `secanal_` and runs on a dedicated bridge network with
resource caps, ports bound to 127.0.0.1 only, and no host bind mounts, so the
untrusted target code stays boxed in. `nuke` tears the whole sandbox down.

SAFETY NOTE: this builds and runs untrusted third-party code. Docker is a
strong boundary but not perfect isolation. Run on a machine you are willing to
treat as the blast radius, keep Docker Desktop updated, and prefer a VM if the
target is high-risk. The sandbox has network egress by default (apps often need
it to boot); set --no-egress to cut it.

CLI:
    python scripts/verify.py net-up
    python scripts/verify.py build  --tag app --path target [--file target/Dockerfile]
    python scripts/verify.py run    --image app --name web --port 8080:8080 [--env K=V ...] [--no-egress]
    python scripts/verify.py compose-up   [--file target/docker-compose.yml]
    python scripts/verify.py probe  --url http://127.0.0.1:8080/ [--method GET] [--data '...'] [--header 'K: V' ...]
    python scripts/verify.py logs   --name web [--tail 200]
    python scripts/verify.py exec   --name web -- id
    python scripts/verify.py ps
    python scripts/verify.py stop   --name web
    python scripts/verify.py nuke
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import TARGET_DIR, run, eprint, configure_stdio  # noqa: E402

configure_stdio()

NET = "secanal_net"
PREFIX = "secanal_"
COMPOSE_PROJECT = "secanal_target"


def _out(obj) -> None:
    print(json.dumps(obj, indent=2, ensure_ascii=False))


def net_up(internal: bool = False) -> dict:
    rc, out, _ = run(["docker", "network", "inspect", NET])
    if rc == 0:
        return {"network": NET, "created": False}
    cmd = ["docker", "network", "create", "--driver", "bridge"]
    if internal:
        cmd.append("--internal")
    cmd.append(NET)
    rc, out, err = run(cmd)
    if rc != 0:
        raise SystemExit(f"[verify] network create failed: {err}")
    return {"network": NET, "created": True}


def build(tag: str, path: str = "target", dockerfile: str | None = None) -> dict:
    image = f"{PREFIX}{tag}"
    ctx = str((Path(path).resolve()))
    cmd = ["docker", "build", "-t", image]
    if dockerfile:
        cmd += ["-f", str(Path(dockerfile).resolve())]
    cmd += [ctx]
    rc, out, err = run(cmd, timeout=3600)
    return {"image": image, "ok": rc == 0, "log_tail": (err or out)[-1500:]}


def run_container(image: str, name: str, ports: list[str], envs: list[str],
                  no_egress: bool = False) -> dict:
    net_up(internal=no_egress)
    full = f"{PREFIX}{name}"
    run(["docker", "rm", "-f", full])
    cmd = [
        "docker", "run", "-d", "--name", full,
        "--network", NET,
        "--memory", "2g", "--cpus", "2", "--pids-limit", "512",
        "--security-opt", "no-new-privileges", "--cap-drop", "ALL",
    ]
    for p in ports:  # bind to loopback only
        host, _, cont = p.partition(":")
        cont = cont or host
        cmd += ["-p", f"127.0.0.1:{host}:{cont}"]
    for e in envs:
        cmd += ["-e", e]
    cmd.append(image if image.startswith(PREFIX) else f"{PREFIX}{image}"
               if not (":" in image or "/" in image) else image)
    rc, out, err = run(cmd, timeout=300)
    return {"name": full, "ok": rc == 0, "id": out.strip()[:12], "error": err.strip()[:400]}


def compose_up(file: str | None = None) -> dict:
    compose = file or _find_compose()
    if not compose:
        raise SystemExit("no docker-compose file found; pass --file")
    cmd = ["docker", "compose", "-p", COMPOSE_PROJECT, "-f", str(Path(compose).resolve()),
           "up", "-d", "--build"]
    rc, out, err = run(cmd, cwd=TARGET_DIR, timeout=3600)
    return {"compose": compose, "ok": rc == 0, "log_tail": (err or out)[-1500:]}


def compose_down(file: str | None = None) -> dict:
    compose = file or _find_compose()
    cmd = ["docker", "compose", "-p", COMPOSE_PROJECT]
    if compose:
        cmd += ["-f", str(Path(compose).resolve())]
    cmd += ["down", "-v", "--remove-orphans"]
    rc, out, err = run(cmd, cwd=TARGET_DIR, timeout=600)
    return {"ok": rc == 0}


def _find_compose() -> str | None:
    for n in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
        p = TARGET_DIR / n
        if p.exists():
            return str(p)
    return None


def probe(url: str, method: str = "GET", data: str | None = None,
          headers: list[str] | None = None, retries: int = 5) -> dict:
    hdrs = {}
    for h in headers or []:
        k, _, v = h.partition(":")
        hdrs[k.strip()] = v.strip()
    body = data.encode("utf-8") if data is not None else None
    last_err = None
    for _ in range(retries):
        try:
            req = urllib.request.Request(url, data=body, headers=hdrs, method=method.upper())
            t0 = time.monotonic()
            with urllib.request.urlopen(req, timeout=15) as resp:
                content = resp.read(65536)
                return {
                    "url": url, "status": resp.status,
                    "elapsed_ms": int((time.monotonic() - t0) * 1000),
                    "headers": dict(resp.headers),
                    "body": content.decode("utf-8", "replace"),
                    "body_len": len(content),
                }
        except urllib.error.HTTPError as e:  # noqa: PERF203
            content = e.read(65536)
            return {"url": url, "status": e.code, "http_error": True,
                    "body": content.decode("utf-8", "replace"), "headers": dict(e.headers or {})}
        except Exception as e:  # noqa: BLE001  (app may still be booting)
            last_err = str(e)
            time.sleep(2)
    return {"url": url, "status": None, "error": last_err}


def logs(name: str, tail: int = 200) -> dict:
    full = name if name.startswith(PREFIX) else f"{PREFIX}{name}"
    rc, out, err = run(["docker", "logs", "--tail", str(tail), full])
    return {"name": full, "logs": (out + err)[-6000:]}


def exec_in(name: str, argv: list[str]) -> dict:
    full = name if name.startswith(PREFIX) else f"{PREFIX}{name}"
    rc, out, err = run(["docker", "exec", full, *argv], timeout=120)
    return {"name": full, "rc": rc, "stdout": out[-4000:], "stderr": err[-2000:]}


def ps() -> dict:
    rc, out, _ = run(["docker", "ps", "-a", "--filter", f"name={PREFIX}",
                      "--format", "{{.Names}}\t{{.Status}}\t{{.Ports}}"])
    return {"containers": [ln for ln in out.splitlines() if ln.strip()]}


def stop(name: str) -> dict:
    full = name if name.startswith(PREFIX) else f"{PREFIX}{name}"
    run(["docker", "rm", "-f", full])
    return {"stopped": full}


def nuke() -> dict:
    """Remove every secanal_* container, volume, the compose project, and the network."""
    compose_down()
    rc, out, _ = run(["docker", "ps", "-aq", "--filter", f"name={PREFIX}"])
    ids = [x for x in out.split() if x]
    if ids:
        run(["docker", "rm", "-f", *ids])
    # named volumes (WP cookie jars etc.)
    rc, vout, _ = run(["docker", "volume", "ls", "-q", "--filter", f"name={PREFIX}"])
    vols = [x for x in vout.split() if x]
    if vols:
        run(["docker", "volume", "rm", "-f", *vols])
    run(["docker", "network", "rm", NET])
    return {"nuked": True, "removed_containers": len(ids), "removed_volumes": len(vols)}


# ===========================================================================
# WordPress plugin dynamic-verification sandbox
# ===========================================================================
# Brings up a real WordPress + MariaDB, installs the plugin under test into it,
# and gives the finding-verifier the tools to run two-principal / injection
# exploits against a live install. The plugin source is `docker cp`-ed in (never
# host-bind-mounted), so instrumentation works like this: the verifier edits the
# PHP in the extracted clone (target/…), calls `wp-sync` to push the change into
# the running container (PHP is interpreted — live immediately, no rebuild), then
# fires the exploit and reads `logs`/`wp-logs` for the [SECANAL] debug lines.
#
# Hardening note: WordPress+apache need their default caps (bind :80, drop to
# www-data), so these containers keep default caps but still run with
# no-new-privileges, resource caps, a dedicated bridge net, and the host port
# bound to 127.0.0.1 only. The DB has no host port at all.

WP_NAME = f"{PREFIX}wp"
DB_NAME = f"{PREFIX}db"
WP_IMAGE = "wordpress:php8.2-apache"
DB_IMAGE = "mariadb:11"
CLI_IMAGE = "wordpress:cli"
CURL_IMAGE = "curlimages/curl:latest"
WP_ROOT = "/var/www/html"
# Canonical URL is the container name on the sandbox net, so in-net tools
# (wp-curl / wp-cli) and WordPress' own redirects all agree. Host port is for a
# human to peek only — agent HTTP should go through `wp-curl`.
SITE_URL = f"http://{WP_NAME}"
ADMIN_USER, ADMIN_PASS = "admin", "WpForge!Admin23456"
SUB_USER, SUB_PASS = "subscriber", "WpForge!Sub23456"


def wp_cli(argv: list[str], timeout: int = 180) -> dict:
    """Run wp-cli against the sandbox WordPress (shares its files via
    --volumes-from). Pass the subcommand without the leading 'wp'."""
    cmd = [
        "docker", "run", "--rm", "--network", NET,
        "--volumes-from", WP_NAME, "--user", "33:33",   # www-data
        CLI_IMAGE, *argv, f"--path={WP_ROOT}",
    ]
    rc, out, err = run(cmd, timeout=timeout)
    return {"rc": rc, "stdout": out[-6000:], "stderr": err[-2000:]}


def wp_sync(slug: str, timeout: int = 180) -> dict:
    """Copy the extracted plugin (target/) into the running WP container's
    wp-content/plugins/<slug>. Call again after editing files to instrument."""
    src = str(TARGET_DIR.resolve())
    dest_parent = f"{WP_NAME}:{WP_ROOT}/wp-content/plugins"
    run(["docker", "exec", WP_NAME, "mkdir", "-p", f"{WP_ROOT}/wp-content/plugins"])
    # copy the plugin dir contents under the slug name
    rc, out, err = run(["docker", "cp", f"{src}/.",
                        f"{WP_NAME}:{WP_ROOT}/wp-content/plugins/{slug}"], timeout=timeout)
    run(["docker", "exec", WP_NAME, "chown", "-R", "www-data:www-data",
         f"{WP_ROOT}/wp-content/plugins/{slug}"])
    return {"synced": rc == 0, "slug": slug, "error": err.strip()[:300]}


def wp_up(slug: str, port: int = 8080, no_egress: bool = False,
          boot_timeout: int = 180) -> dict:
    """Stand up WordPress + MariaDB, install the plugin, activate it, and seed an
    admin + a subscriber (principals A/B for authz tests)."""
    net_up(internal=no_egress)
    run(["docker", "rm", "-f", WP_NAME, DB_NAME])

    # --- database (no host port) ---
    db_cmd = [
        "docker", "run", "-d", "--name", DB_NAME, "--network", NET,
        "--memory", "1g", "--cpus", "2", "--pids-limit", "512",
        "--security-opt", "no-new-privileges",
        "-e", "MARIADB_ROOT_PASSWORD=root",
        "-e", "MARIADB_DATABASE=wordpress",
        "-e", "MARIADB_USER=wp", "-e", "MARIADB_PASSWORD=wp",
        DB_IMAGE,
    ]
    rc, _, err = run(db_cmd, timeout=300)
    if rc != 0:
        return {"ok": False, "stage": "db", "error": err.strip()[:400]}

    # --- wordpress (host port on loopback only) ---
    wp_cmd = [
        "docker", "run", "-d", "--name", WP_NAME, "--network", NET,
        "-p", f"127.0.0.1:{port}:80",
        "--memory", "2g", "--cpus", "2", "--pids-limit", "512",
        "--security-opt", "no-new-privileges",
        "-e", f"WORDPRESS_DB_HOST={DB_NAME}",
        "-e", "WORDPRESS_DB_USER=wp", "-e", "WORDPRESS_DB_PASSWORD=wp",
        "-e", "WORDPRESS_DB_NAME=wordpress",
        "-e", "WORDPRESS_DEBUG=1",
        WP_IMAGE,
    ]
    rc, _, err = run(wp_cmd, timeout=300)
    if rc != 0:
        return {"ok": False, "stage": "wp", "error": err.strip()[:400]}

    # --- wait for DB connectivity via wp-cli ---
    deadline = time.monotonic() + boot_timeout
    ready = False
    while time.monotonic() < deadline:
        if wp_cli(["db", "check"]).get("rc") == 0:
            ready = True
            break
        time.sleep(3)
    if not ready:
        return {"ok": False, "stage": "db-wait", "logs": logs(WP_NAME).get("logs", "")}

    # --- install core + activate plugin + seed principals ---
    inst = wp_cli(["core", "install", f"--url={SITE_URL}", "--title=WP-FORGE",
                   f"--admin_user={ADMIN_USER}", f"--admin_password={ADMIN_PASS}",
                   "--admin_email=admin@wp-forge.test", "--skip-email"])
    synced = wp_sync(slug)
    act = wp_cli(["plugin", "activate", slug])
    wp_cli(["user", "create", SUB_USER, "sub@wp-forge.test",
            "--role=subscriber", f"--user_pass={SUB_PASS}"])

    return {
        "ok": act.get("rc") == 0, "slug": slug, "site_url": SITE_URL,
        "host_url": f"http://127.0.0.1:{port}",
        "admin": {"user": ADMIN_USER, "pass": ADMIN_PASS},
        "subscriber": {"user": SUB_USER, "pass": SUB_PASS},
        "installed": inst.get("rc") == 0, "plugin_synced": synced.get("synced"),
        "activated": act.get("rc") == 0, "activate_out": (act.get("stdout") or act.get("stderr")),
    }


def wp_login(user: str, password: str, jar: str) -> dict:
    """Log a principal in and persist the session cookies in a named jar, so
    later wp-curl calls with the same jar act as that user. jar names the
    principal (e.g. 'A' for admin, 'B' for subscriber)."""
    return wp_curl("/wp-login.php", method="POST", jar=jar, follow=True,
                   data=(f"log={urllib.parse.quote(user)}&pwd={urllib.parse.quote(password)}"
                         "&wp-submit=Log+In&testcookie=1"),
                   headers=["Content-Type: application/x-www-form-urlencoded",
                            "Cookie: wordpress_test_cookie=WP+Cookie+check"])


def wp_curl(path: str, method: str = "GET", data: str | None = None,
            headers: list[str] | None = None, jar: str = "anon",
            follow: bool = False) -> dict:
    """HTTP against the sandbox WordPress from *inside* the net (so redirects to
    the site URL resolve). Cookies persist per-principal in a named jar volume,
    which is how the two-principal test replays one user's request as another."""
    vol = f"{PREFIX}jar_{jar}"
    url = f"{SITE_URL}{path if path.startswith('/') else '/' + path}"
    cmd = [
        "docker", "run", "--rm", "--network", NET,
        "-v", f"{vol}:/jar",
        CURL_IMAGE, "-sS", "-i", "-m", "30",
        "-c", "/jar/cookies", "-b", "/jar/cookies", "-X", method.upper(),
    ]
    for h in (headers or []):
        cmd += ["-H", h]
    if follow:
        cmd.append("-L")
    if data is not None:
        cmd += ["--data", data]
    cmd.append(url)
    rc, out, err = run(cmd, timeout=90)
    return {"url": url, "method": method.upper(), "jar": jar, "rc": rc,
            "response": (out or "")[-12000:], "error": err.strip()[:400]}


def main() -> None:
    ap = argparse.ArgumentParser(description="secanal dynamic-verification sandbox")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("net-up")
    p = sub.add_parser("build"); p.add_argument("--tag", required=True); p.add_argument("--path", default="target"); p.add_argument("--file")
    p = sub.add_parser("run"); p.add_argument("--image", required=True); p.add_argument("--name", required=True)
    p.add_argument("--port", action="append", default=[]); p.add_argument("--env", action="append", default=[]); p.add_argument("--no-egress", action="store_true")
    p = sub.add_parser("compose-up"); p.add_argument("--file")
    p = sub.add_parser("compose-down"); p.add_argument("--file")
    p = sub.add_parser("probe"); p.add_argument("--url", required=True); p.add_argument("--method", default="GET")
    p.add_argument("--data"); p.add_argument("--header", action="append", default=[])
    p = sub.add_parser("logs"); p.add_argument("--name", required=True); p.add_argument("--tail", type=int, default=200)
    p = sub.add_parser("exec"); p.add_argument("--name", required=True); p.add_argument("argv", nargs=argparse.REMAINDER)
    sub.add_parser("ps")
    p = sub.add_parser("stop"); p.add_argument("--name", required=True)
    sub.add_parser("nuke")

    # --- WordPress plugin sandbox ---
    p = sub.add_parser("wp-up"); p.add_argument("--slug", required=True)
    p.add_argument("--port", type=int, default=8080); p.add_argument("--no-egress", action="store_true")
    p.add_argument("--boot-timeout", type=int, default=180)
    p = sub.add_parser("wp-cli"); p.add_argument("--slug"); p.add_argument("argv", nargs=argparse.REMAINDER)
    p = sub.add_parser("wp-sync"); p.add_argument("--slug", required=True)
    p = sub.add_parser("wp-login"); p.add_argument("--user", required=True); p.add_argument("--password", required=True); p.add_argument("--jar", required=True)
    p = sub.add_parser("wp-curl"); p.add_argument("--path", required=True); p.add_argument("--method", default="GET")
    p.add_argument("--data"); p.add_argument("--header", action="append", default=[]); p.add_argument("--jar", default="anon"); p.add_argument("--follow", action="store_true")

    a = ap.parse_args()
    if a.cmd == "net-up":
        _out(net_up())
    elif a.cmd == "build":
        _out(build(a.tag, a.path, a.file))
    elif a.cmd == "run":
        _out(run_container(a.image, a.name, a.port, a.env, a.no_egress))
    elif a.cmd == "compose-up":
        _out(compose_up(a.file))
    elif a.cmd == "compose-down":
        _out(compose_down(a.file))
    elif a.cmd == "probe":
        _out(probe(a.url, a.method, a.data, a.header))
    elif a.cmd == "logs":
        _out(logs(a.name, a.tail))
    elif a.cmd == "exec":
        argv = a.argv[1:] if a.argv and a.argv[0] == "--" else a.argv
        _out(exec_in(a.name, argv))
    elif a.cmd == "ps":
        _out(ps())
    elif a.cmd == "stop":
        _out(stop(a.name))
    elif a.cmd == "nuke":
        _out(nuke())
    elif a.cmd == "wp-up":
        _out(wp_up(a.slug, a.port, a.no_egress, a.boot_timeout))
    elif a.cmd == "wp-cli":
        argv = a.argv[1:] if a.argv and a.argv[0] == "--" else a.argv
        _out(wp_cli(argv))
    elif a.cmd == "wp-sync":
        _out(wp_sync(a.slug))
    elif a.cmd == "wp-login":
        _out(wp_login(a.user, a.password, a.jar))
    elif a.cmd == "wp-curl":
        _out(wp_curl(a.path, a.method, a.data, a.header, a.jar, a.follow))


if __name__ == "__main__":
    main()
