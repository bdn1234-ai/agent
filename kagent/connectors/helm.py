"""Chạy helm thật (kèm plugin helm-diff, helm-drift) trên cụm của kết nối Kubernetes; chọn helm 3 hoặc helm 2 (Tiller) theo kết nối.

Helm 3 lưu release trong Secret của namespace, helm 2 nói chuyện với Tiller qua port-forward; cả hai đều cần token nhóm quản trị (k8s_rbac).
Vì vậy RBAC không phân biệt được đọc/ghi như với kubectl; kagent tự phân lệnh theo nội dung:
- helm_read: list, status, history, show/inspect, template, get notes/metadata, diff (không --show-secrets), drift (chỉ helm 3).
- helm_write: install, upgrade, rollback. Chạy thử bằng helm diff (che giá trị Secret), hoàn tác bằng helm rollback.
- helm_admin: uninstall/delete, test, get values/manifest/hooks/all, diff --show-secrets.
Không đọc file trên máy chủ kagent: chart lấy từ --repo URL, oci:// (helm 3) hoặc URL .tgz; values truyền qua tham số values với -f -.
Không có helm repo add, registry login, plugin install: mỗi lần chạy là HOME tạm, không giữ cấu hình.
"""
from __future__ import annotations

import os
import re
import shlex
import shutil
import tempfile

import httpx
import yaml

from .. import net
from . import k8s, kubectl
from .base import ConnectorError, clip, integer

HELM = os.environ.get("KAGENT_HELM") or "helm"
HELM2 = os.environ.get("KAGENT_HELM2") or "helm2"
PLUGINS = os.environ.get("KAGENT_HELM_PLUGINS") or "/opt/helm/plugins"
PLUGINS2 = os.environ.get("KAGENT_HELM2_PLUGINS") or "/opt/helm2/plugins"
# Test thay bằng callable(argv, env, stdin, timeout) -> (mã thoát, stdout, stderr, hết giờ).
runner = None

TOOL = {"read": "helm_read", "write": "helm_write", "admin": "helm_admin"}
PROFILES = ("read", "write", "admin")
LABEL = {"read": "đọc", "write": "ghi", "admin": "quản trị"}
DIFF_ACTIONS = {"read": {"upgrade", "rollback", "revision", "release", "version"}}
# Bảng lệnh theo phiên bản. need None = phụ thuộc hành động (ACTIONS).
DIALECTS = {
    "3": {"aliases": {"ls": "list", "hist": "history", "un": "uninstall", "del": "uninstall", "delete": "uninstall", "uninstal": "uninstall",
                      "inspect": "show"},
          "subs": {"list": "read", "status": "read", "history": "read", "show": "read", "template": "read", "version": "read",
                   "get": None, "diff": None, "drift": "read", "install": "write", "upgrade": "write", "rollback": "write",
                   "uninstall": "admin", "test": "admin"},
          "actions": {"show": {"read": {"chart", "values", "readme", "crds", "all"}},
                      "get": {"read": {"notes", "metadata"}, "admin": {"values", "manifest", "hooks", "all"}},
                      "diff": DIFF_ACTIONS, "drift": {"read": {"run", "all", "version"}}},
          "uninstall": "uninstall",
          "short": {"n": "namespace", "o": "output", "f": "values", "l": "selector", "a": "all", "A": "all-namespaces", "q": "short",
                    "d": "disable-error-on-drift", "C": "context", "s": "show-only"},
          "blocked": set()},
    # helm 2: -n là --name; Tiller và TLS tới Tiller lấy từ cấu hình kết nối. Không có template vì helm 2 template chỉ đọc chart trên máy.
    "2": {"aliases": {"ls": "list", "hist": "history", "del": "delete", "uninstall": "delete", "un": "delete", "show": "inspect"},
          "subs": {"list": "read", "status": "read", "history": "read", "inspect": "read", "version": "read",
                   "get": None, "diff": None, "install": "write", "upgrade": "write", "rollback": "write", "delete": "admin", "test": "admin"},
          "actions": {"inspect": {"read": {"chart", "values", "readme"}}, "get": {"read": {"notes"}, "admin": {"values", "manifest", "hooks"}},
                      "diff": DIFF_ACTIONS},
          "uninstall": "delete",
          "short": {"n": "name", "o": "output", "f": "values", "a": "all", "q": "short", "d": "date", "r": "reverse", "C": "context"},
          "blocked": {"home", "host", "tiller-namespace", "tls", "tls-ca-cert", "tls-cert", "tls-key", "tls-verify", "tls-hostname"}},
}
WRITES = {"install", "upgrade", "rollback", "uninstall", "delete", "test"}
# Đọc file hoặc chạy chương trình trên máy chủ kagent, đổi danh tính/đích đến, hoặc ghi cấu hình ngoài thư mục tạm.
BLOCKED = {"kubeconfig", "kube-context", "kube-token", "kube-as-user", "kube-as-group", "kube-apiserver", "kube-ca-file",
           "kube-insecure-skip-tls-verify", "kube-tls-server-name", "registry-config", "repository-config", "repository-cache",
           "post-renderer", "post-renderer-args", "set-file", "ca-file", "cert-file", "key-file", "keyring", "verify", "username", "password",
           "pass-credentials", "output-dir", "temp-path", "custom-diff", "skip-cleaning", "report", "plugins", "dry-run", "post-render"}
# Flag nhận giá trị (dạng --x y); còn lại coi là flag bật/tắt. Chỉ để tìm đúng tham số vị trí (tên release, chart).
VALUED = {"namespace", "output", "values", "set", "set-string", "set-json", "set-literal", "repo", "version", "timeout", "description",
          "name-template", "labels", "max", "filter", "selector", "revision", "kind", "name", "skip", "ignore-hooks", "concurrency",
          "log-level", "regex", "suppress", "suppress-output-line-regex", "find-renames", "api-versions", "kube-version", "skip-release",
          "history-max", "context", "output-format", "time-format", "show-only", "release-name", "wait-for", "burst-limit", "qps", "template",
          "execute", "offset", "col-width", "tiller-connection-timeout", "notes"}
# helm diff không có các flag chỉ dành cho lệnh ghi này; bỏ đi khi đổi install/upgrade thành diff để chạy thử.
DIFF_DROP = {"wait", "wait-for-jobs", "atomic", "rollback-on-failure", "timeout", "create-namespace", "description", "history-max", "cleanup-on-fail",
             "force", "force-replace", "force-conflicts", "dependency-update", "dep-up", "generate-name", "name-template", "install",
             "render-subchart-notes", "take-ownership", "labels", "skip-schema-validation", "replace", "debug", "hide-notes", "enable-dns",
             "server-side", "devel", "name", "max-history", "recreate-pods", "no-hooks"}
NAME = re.compile(r"^[A-Za-z0-9][-A-Za-z0-9_.+]{0,252}$")
MAX_COMMAND, MAX_VALUES = 4000, 500_000
VERSIONS = ("3", "2")


def _fail(message: str):
    raise ConnectorError(message)


def version(p: dict) -> str:
    v = str(p.get("helm_version") or "3").strip().lstrip("v").split(".")[0]
    if v not in VERSIONS:
        _fail(f"helm_version phải là 3 hoặc 2, không phải {p.get('helm_version')}")
    return v


def validate_params(p: dict) -> None:
    version(p)
    if bool(p.get("tiller_client_cert")) != bool(p.get("tiller_client_key")):
        _fail("tiller_client_cert và tiller_client_key phải điền cùng nhau")
    ns = p.get("tiller_namespace")
    if ns and not re.match(r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$", ns):
        _fail(f"tiller_namespace không hợp lệ: {ns}")


def _flag(a: str, short: dict) -> tuple[str | None, str | None]:
    """(tên flag dạng dài, giá trị viết liền) của một token; (None, None) nếu không phải flag."""
    if a.startswith("--") and len(a) > 2:
        name, eq, value = a[2:].partition("=")
        return name, (value if eq else None)
    if a.startswith("-") and len(a) > 1 and not a[1:].isdigit():
        letter, rest = a[1], a[2:]
        if letter not in short or (rest and not rest.startswith("=")):
            _fail(f"flag {a} không được dùng; viết tách flag ngắn (ví dụ -f -), flag khác dùng dạng dài --tên")
        return short[letter], (rest[1:] if rest else None)
    return None, None


def _check_chart(ref: str, allow_private: bool | None, ver: str) -> None:
    hint = "oci://..., https://.../chart.tgz" if ver == "3" else "https://.../chart.tgz"
    if "://" in ref:
        scheme = ref.split("://", 1)[0].lower()
        if scheme == "oci" and ver == "3":
            if allow_private is not None:
                u = httpx.URL("https://" + ref.split("://", 1)[1])
                net.check_host(u.host, u.port or 443, allow_private)
            return
        if scheme in ("http", "https"):
            if allow_private is not None:
                net.check_url(ref, allow_private)
            return
        _fail(f"không hỗ trợ chart {ref} với helm {ver}; dùng {hint} hoặc --repo URL kèm tên chart")
    if not NAME.match(ref) or ".." in ref:
        _fail(f"'{ref}' không phải tên hợp lệ; kagent không đọc chart trên máy chủ và không có helm repo add, "
              f"chart phải là {hint} hoặc tên chart kèm --repo https://...")


def parse(command, profile: str, allow_private: bool | None = False, ver: str = "3") -> tuple[list[str], dict]:
    """allow_private=None: bỏ kiểm tra mạng (chỉ phân loại lệnh, không tra DNS)."""
    d = DIALECTS[ver]
    if not isinstance(command, str) or not command.strip():
        _fail("thiếu tham số command, ví dụ: list")
    if len(command) > MAX_COMMAND:
        _fail(f"lệnh dài quá {MAX_COMMAND} ký tự")
    try:
        argv = shlex.split(command)
    except ValueError as exc:
        _fail(f"lệnh không hợp lệ: {exc}")
    if argv and argv[0] in ("helm", "helm2", "helm3"):
        argv = argv[1:]
    argv, stages = kubectl._split_pipeline(argv)
    filters = [kubectl._filter(stage) for stage in stages]
    if not argv or argv[0].startswith("-"):
        _fail("lệnh phải bắt đầu bằng lệnh con của helm, flag đặt phía sau, ví dụ: status web")
    sub = d["aliases"].get(argv[0], argv[0])
    argv = [sub, *argv[1:]]
    if sub == "drift" and ver == "2":
        _fail("helm-drift chỉ chạy với helm 3; với helm 2 dùng diff release hoặc diff revision")
    if sub not in d["subs"]:
        _fail(f"helm {sub} không được hỗ trợ với helm {ver} (chỉ hỗ trợ: {', '.join(sorted(d['subs']))})")
    action, need = None, d["subs"][sub]
    if sub in d["actions"]:
        acts = d["actions"][sub]
        known = set().union(*acts.values())
        action = argv[1] if len(argv) > 1 else None
        if action not in known:
            _fail(f"helm {sub} cần hành động ngay sau, một trong: {', '.join(sorted(known))}")
        need = next(p for p in PROFILES if action in acts.get(p, set()))
    stdin, positionals, flags, values = False, [], set(), {}
    i = 2 if action else 1
    while i < len(argv):
        a = argv[i]
        name, value = _flag(a, d["short"])
        if name is None:
            positionals.append(a)
            i += 1
            continue
        if name in BLOCKED or name in d["blocked"]:
            _fail(f"flag --{name} không được dùng qua kagent" + ("; Tiller cấu hình ở kết nối" if name in d["blocked"] else ""))
        if name.startswith("kube-") and name != "kube-version":
            _fail(f"flag --{name} không được dùng qua kagent; kagent tự cấp kết nối tới cụm")
        if name in VALUED and value is None:
            value = argv[i + 1] if i + 1 < len(argv) else ""
            i += 1
        flags.add(name)
        values[name] = value
        if name == "values":
            if value != "-":
                _fail("chỉ được -f - ; truyền nội dung values qua tham số values")
            stdin = True
        if name == "repo" and allow_private is not None:
            net.check_url(value, allow_private)
        if name == "show-secrets" and need == "read":
            need = "admin"
        i += 1
    for ref in positionals:
        _check_chart(ref, allow_private, ver)
    if PROFILES.index(need) > PROFILES.index(profile):
        _fail(f"helm {sub}{' ' + action if action else ''}{' --show-secrets' if 'show-secrets' in flags else ''} thuộc nhóm "
              f"{LABEL[need]}, hãy dùng công cụ {TOOL[need]}")
    read_only = sub not in WRITES
    if filters and not read_only:
        _fail("chỉ lệnh đọc mới được lọc qua | grep/head/tail")
    if sub == "install":
        release = values.get("name") if ver == "2" else (positionals[0] if len(positionals) >= 2 else None)
        chart = positionals[0] if ver == "2" else (positionals[1] if len(positionals) >= 2 else None)
    else:
        release = positionals[0] if positionals and sub in WRITES | {"status", "history"} else None
        chart = positionals[1] if sub == "upgrade" and len(positionals) >= 2 else None
    return argv, {"sub": sub, "action": action, "key": f"{sub} {action}" if action else sub, "stdin": stdin, "read_only": read_only,
                  "filters": filters, "pipe": " | ".join(shlex.join(s) for s in stages), "positionals": positionals, "flags": flags,
                  "release": release, "chart": chart, "namespace": values.get("namespace"), "version": ver}


def namespace(info: dict, p: dict) -> str:
    return info.get("namespace") or p.get("namespace") or "default"


def _route(url: str, p: dict) -> str | None:
    from .. import proxy
    try:
        route = proxy.routes(url.replace("oci://", "https://", 1), p.get("proxy"))[0]
    except proxy.ProxyError as exc:
        raise net.NetError(str(exc)) from exc
    return None if route == "DIRECT" else route


def _chart_route(argv: list[str], p: dict) -> str | None:
    """Proxy cho việc tải chart (helm chỉ nhận một HTTPS_PROXY): theo --repo hoặc URL chart đầu tiên."""
    urls = [a for a in argv if "://" in a]
    for i, a in enumerate(argv):
        if a == "--repo" and i + 1 < len(argv):
            urls.insert(0, argv[i + 1])
        elif a.startswith("--repo="):
            urls.insert(0, a.split("=", 1)[1])
    return _route(urls[0], p) if urls else None


def _legacy_kubeconfig(config: str, api_url: str) -> tuple[str, str | None]:
    """client-go của helm 2 không biết tls-server-name, proxy-url: trỏ theo tên máy (host đã qua kiểm tra IP), proxy đưa sang env."""
    doc = yaml.safe_load(config)
    cluster = doc["clusters"][0]["cluster"]
    proxy_url = cluster.pop("proxy-url", None)
    if cluster.pop("tls-server-name", None) is not None or proxy_url:
        u = httpx.URL(api_url)
        cluster["server"] = f"{u.scheme}://{u.host}:{u.port or net.default_port(u.scheme)}{u.path.rstrip('/')}"
    return yaml.safe_dump(doc), proxy_url


def _write(path: str, text: str) -> str:
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w", encoding="utf-8") as f:
        f.write(text)
    return path


def _helm2_home(d: str) -> str:
    """HELM_HOME tối thiểu thay cho `helm init --client-only` (lệnh đó tải stable repo)."""
    home = os.path.join(d, "helm")
    for sub in ("repository/cache", "repository/local", "plugins", "starters", "cache/archive"):
        os.makedirs(os.path.join(home, sub), exist_ok=True)
    with open(os.path.join(home, "repository", "repositories.yaml"), "w", encoding="utf-8") as f:
        f.write("apiVersion: v1\nrepositories: []\n")
    return home


def _exec(p: dict, argv: list[str], values: str | None, timeout: int, interruptible: bool, ns: str | None = None) -> tuple[int, str, str, bool]:
    ver = version(p)
    exe = shutil.which(HELM if ver == "3" else HELM2)
    if exe is None and runner is None:
        _fail("máy chủ kagent chưa cài helm" + (" 2" if ver == "2" else ""))
    c = k8s._conn(p)
    api = httpx.URL(c["api_url"])
    config = kubectl.kubeconfig(p, kubectl._token(p, "admin"))
    api_proxy = None
    if ver == "2":
        config, api_proxy = _legacy_kubeconfig(config, c["api_url"])
    route = _chart_route(argv, p)
    with tempfile.TemporaryDirectory(prefix="kagent-helm-") as d:
        path = _write(os.path.join(d, "config"), config)
        if values is not None:
            # helm-drift không đọc values từ stdin, nên mọi lệnh đều nhận file tạm thay cho "-".
            vpath = _write(os.path.join(d, "values.yaml"), values)
            argv = [vpath if a == "-" and i and argv[i - 1] in ("-f", "--values") else a for i, a in enumerate(argv)]
            argv = [f"--values={vpath}" if a == "--values=-" else f"-f={vpath}" if a == "-f=-" else a for a in argv]
        tools = os.path.dirname(shutil.which(kubectl.KUBECTL) or "/usr/local/bin/kubectl")  # helm-drift gọi kubectl diff
        env = {"PATH": f"{os.path.dirname(exe or '/usr/local/bin/helm')}:{tools}:/usr/local/bin:/usr/bin:/bin", "HOME": d, "KUBECONFIG": path,
               "LANG": "C.UTF-8"}
        if ver == "3":
            env.update({"HELM_PLUGINS": PLUGINS, "HELM_CACHE_HOME": os.path.join(d, "cache"), "HELM_CONFIG_HOME": os.path.join(d, "config.d"),
                        "HELM_DATA_HOME": os.path.join(d, "data"), "HELM_NAMESPACE": ns or p.get("namespace") or "default"})
        else:
            env.update({"HELM_HOME": _helm2_home(d), "HELM_PLUGIN": PLUGINS2, "TILLER_NAMESPACE": p.get("tiller_namespace") or "kube-system"})
            if p.get("tiller_client_cert"):
                env.update({"HELM_TLS_ENABLE": "true", "HELM_TLS_CERT": _write(os.path.join(d, "tls.crt"), p["tiller_client_cert"]),
                            "HELM_TLS_KEY": _write(os.path.join(d, "tls.key"), p["tiller_client_key"])})
                if p.get("tiller_ca_cert"):
                    env.update({"HELM_TLS_VERIFY": "true", "HELM_TLS_CA_CERT": _write(os.path.join(d, "ca.crt"), p["tiller_ca_cert"])})
        if api_proxy:
            # helm 2 không đọc proxy-url, API server và chart dùng chung một proxy qua env.
            env.update({"HTTPS_PROXY": api_proxy, "HTTP_PROXY": api_proxy})
        elif route:
            # API server đi thẳng (IP riêng trong kubeconfig); NO_PROXY giữ nó khỏi đi qua proxy của chart.
            server = httpx.URL(yaml.safe_load(config)["clusters"][0]["cluster"]["server"])
            env.update({"HTTPS_PROXY": route, "HTTP_PROXY": route, "NO_PROXY": f"{api.host},{server.host}"})
        full = [exe or (HELM if ver == "3" else HELM2), *argv]
        if runner is not None:
            return runner(full, env, None, timeout)
        return kubectl.spawn(full, env, d, None, timeout + (5 if interruptible else 30), interruptible)


def _installed(ver: str, plugin: str) -> bool:
    return runner is not None or os.path.isdir(os.path.join(PLUGINS if ver == "3" else PLUGINS2, plugin))


def _prepare(argv: list[str], info: dict, timeout: int) -> list[str]:
    sub, ver = info["sub"], info["version"]
    if sub in ("diff", "drift") and not _installed(ver, sub):
        _fail(f"máy chủ kagent chưa cài plugin helm-{sub}" + (" cho helm 2" if ver == "2" else ""))
    if sub == "drift" and info["action"] in ("run", "all") and "disable-error-on-drift" not in info["flags"]:
        argv = [*argv, "--disable-error-on-drift"]  # có drift là kết quả, không phải lỗi
    if sub in ("diff", "drift") and "no-color" not in info["flags"]:
        argv = [*argv, "--no-color"]
    if sub in WRITES - {"test"} and "timeout" not in info["flags"]:
        # helm tự dừng chờ trước khi kagent giết tiến trình, release không kẹt pending. helm 2 nhận số giây, helm 3 nhận duration.
        argv = [*argv, f"--timeout={timeout}" + ("s" if ver == "3" else "")]
    return argv


def to_diff(argv: list[str], info: dict) -> list[str] | None:
    """Lệnh helm diff tương ứng với install/upgrade/rollback, để chạy thử. None nếu không có."""
    sub, short = info["sub"], DIALECTS[info["version"]]["short"]
    rest, i = [], 1
    while i < len(argv):
        name, value = _flag(argv[i], short)
        if name is None:
            i += 1
            continue
        take = name in VALUED and value is None
        if name not in DIFF_DROP:
            rest.append(argv[i])
            if take and i + 1 < len(argv):
                rest.append(argv[i + 1])
        i += 2 if take else 1
    pos = info["positionals"]
    if sub == "rollback":
        return ["diff", "rollback", pos[0], *pos[1:2], *rest] if pos else None
    if sub in ("install", "upgrade") and info["release"] and info["chart"]:
        return ["diff", "upgrade", info["release"], info["chart"], "--allow-unreleased", *rest]
    return None


def _run(p: dict, args: dict, profile: str, dry: bool = False) -> dict:
    argv, info = parse(args.get("command"), profile, p.get("_allow_private", False), version(p))
    values = args.get("values")
    if values is not None and (not isinstance(values, str) or len(values) > MAX_VALUES):
        _fail(f"values phải là chuỗi YAML tối đa {MAX_VALUES} ký tự")
    if info["stdin"] and not values:
        _fail("lệnh có -f - nhưng thiếu tham số values")
    if values and not info["stdin"]:
        _fail("có values thì lệnh phải có -f -")
    timeout = integer(args, "timeout_seconds", 60 if info["read_only"] else 300, 1, 600)
    if dry:
        if info["read_only"]:
            return {"read_only": True, "note": "lệnh chỉ đọc, không cần chạy thử"}
        return _dry(p, argv, info, values, timeout)
    argv = _prepare(argv, info, timeout)
    code, out, err, timed_out = _exec(p, argv, values, timeout, info["read_only"], info["namespace"])
    command = "helm " + shlex.join(argv)
    if info["filters"]:
        command += " | " + info["pipe"]
        out = kubectl._apply_filters(out, info["filters"])
    result = {"command": command, "exit_code": code, "stdout": clip(out), "stderr": clip(err, 5000)}
    if timed_out:
        result["timed_out"] = True
    elif code != 0 and not (info["sub"] == "diff" and code == 2 and "detailed-exitcode" in info["flags"]):
        _fail(f"helm lỗi (mã {code}): {clip(kubectl._error_text(err or out), 1500)}")
    if info["filters"] and not out:
        result["note"] = "không có dòng nào khớp bộ lọc"
    return result


def _dry(p: dict, argv: list[str], info: dict, values: str | None, timeout: int) -> dict:
    """Chạy thử bằng helm diff (giá trị Secret bị che). helm --dry-run in cả Secret ra nên chỉ dùng khi thiếu plugin, và bỏ stdout."""
    if info["sub"] in ("uninstall", "delete", "test"):
        _fail(f"helm {info['sub']} không có chế độ chạy thử")
    ver = info["version"]
    diff = to_diff(argv, info)
    if diff is not None and _installed(ver, "diff"):
        diff = [*diff, "--no-color"]
        code, out, err, timed_out = _exec(p, diff, values, timeout, True, info["namespace"])
        if timed_out or code != 0:
            _fail(f"helm diff lỗi (mã {code}): {clip(kubectl._error_text(err or out), 1500)}")
        return {"command": "helm " + shlex.join(diff), "diff": clip(out) or "không có khác biệt"}
    dry = [*argv, "--dry-run=server" if ver == "3" else "--dry-run"]
    code, out, err, timed_out = _exec(p, dry, values, timeout, True, info["namespace"])
    if timed_out or code != 0:
        _fail(f"helm chạy thử lỗi (mã {code}): {clip(kubectl._error_text(err or out), 1500)}")
    return {"command": "helm " + shlex.join(dry), "note": "chạy thử qua; không hiện manifest vì có thể chứa Secret"
            + ("" if _installed(ver, "diff") else ", cài plugin helm-diff để xem khác biệt")}


def run_read(p, args):
    return _run(p, args, "read")


def run_write(p, args):
    return _run(p, args, "write")


def check_write(p, args):
    return _run(p, args, "write", dry=True)


def run_admin(p, args):
    return _run(p, args, "admin")


def check_admin(p, args):
    return _run(p, args, "admin", dry=True)


def trusted_output(args: dict) -> bool:
    """helm list và version chỉ trả tên, trạng thái, phiên bản; còn lại có NOTES, mô tả, manifest do người viết chart ghi."""
    try:
        argv, info = parse(args.get("command"), "admin", allow_private=None)
    except ConnectorError:
        return False
    return info["key"] in ("list", "version")
