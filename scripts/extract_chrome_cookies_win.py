"""Extract Yandex/Lavka cookies from the local Chrome profile (Windows).

Chrome MUST be fully closed first: while it runs, its cookie database is
exclusively locked and cannot be read even for a copy.

This reads Chrome's cookie store, unwraps the AES key from Local State via
Windows DPAPI, and writes the Yandex session cookies into the Lavka MCP
config so the server can authenticate as you.

    python scripts/extract_chrome_cookies_win.py

# (close Chrome first). Requires the `cryptography` package.
# Falls back to nothing destructive — only reads cookies and updates config.
# NEVER prints cookie values.
"""
import base64
import ctypes
import glob
import json
import os
import shutil
import sqlite3
import sys
import tempfile
from ctypes import wintypes
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from yandex_lavka_mcp.config import load_config, save_config  # noqa: E402

CHROME_DIR = Path(os.environ["LOCALAPPDATA"]) / "Google" / "Chrome" / "User Data"
WANTED_SUFFIX = (".yandex.ru", "yandex.ru", ".lavka.yandex.ru", "lavka.yandex.ru")


class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def dpapi_unprotect(blob: bytes) -> bytes:
    out = DATA_BLOB()
    buf = ctypes.create_string_buffer(blob, len(blob))
    src = DATA_BLOB(len(blob), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    if not ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(src), None, None, None, None, 0, ctypes.byref(out)
    ):
        raise RuntimeError("CryptUnprotectData failed")
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(out.pbData)


def master_key() -> bytes:
    state = json.loads((CHROME_DIR / "Local State").read_text(encoding="utf-8"))
    raw = base64.b64decode(state["os_crypt"]["encrypted_key"])
    assert raw.startswith(b"DPAPI"), "unexpected key prefix"
    return dpapi_unprotect(raw[len(b"DPAPI"):])  # 32-byte AES key


def decrypt_value(enc: bytes, key: bytes) -> str:
    if not enc:
        return ""
    if enc[:3] not in (b"v10", b"v11"):
        try:
            return enc.decode("utf-8", "ignore")
        except Exception:
            return ""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce, ct = enc[3:15], enc[15:]
    try:
        return AESGCM(key).decrypt(nonce, ct, None).decode("utf-8")
    except Exception:
        return ""


def read_profile(cookie_db: Path, key: bytes) -> dict:
    tmpdir = Path(tempfile.mkdtemp())
    # copy main db + any siblings (wal/journal) so the snapshot is consistent
    for sib in glob.glob(str(cookie_db.parent / (cookie_db.name + "*"))):
        try:
            shutil.copy2(sib, tmpdir / Path(sib).name)
        except OSError:
            pass
    out = {}
    try:
        con = sqlite3.connect(f"file:{tmpdir / cookie_db.name}?immutable=1", uri=True)
        has = con.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='cookies'"
        ).fetchone()
        rows = con.execute(
            "SELECT host_key, name, encrypted_value, value, expires_utc FROM cookies"
        ).fetchall() if has else []
        con.close()
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    for host, name, enc, plain, exp in rows:
        if not any(host == w or host.endswith(w) for w in WANTED_SUFFIX):
            continue
        val = plain if plain else decrypt_value(enc, key)
        if val:
            out[name] = (val, exp)
    return out


def webkit_ts(us: int) -> str:
    if not us:
        return "session"
    try:
        return datetime.fromtimestamp(us / 1e6 - 11644473600, tz=timezone.utc).strftime("%Y-%m-%d")
    except Exception:
        return "?"


def main() -> int:
    key = master_key()
    best, best_profile = {}, None
    for db in glob.glob(str(CHROME_DIR / "*" / "Network" / "Cookies")):
        prof = Path(db).parts[-3]
        got = read_profile(Path(db), key)
        if ("Session_id" in got or "Session_id2" in got) and len(got) > len(best):
            best, best_profile = got, prof
    if not best:
        print("No Yandex session cookies in Chrome. Log into lavka.yandex.ru first.", file=sys.stderr)
        return 1
    values = {k: v for k, (v, _) in best.items()}
    config = load_config()
    config.cookies.update(values)
    path = save_config(config)
    print(f"Profile: {best_profile}")
    print(f"Saved {len(values)} cookies to {path}")
    for k in ("Session_id", "sessionid2", "sessar", "yandexuid", "L", "isa", "lavka__auth-proxy-ct"):
        if k in best:
            print(f"  {k}: expires {webkit_ts(best[k][1])}")
    print(f"Session cookie present: {config.is_authenticated()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
