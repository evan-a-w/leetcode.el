#!/usr/bin/env python3
"""Retrieve a small set of cookies from local macOS browser profiles.

This helper is intentionally narrow:
- It only reads browser cookies for a requested domain.
- It only prints requested cookie names when --keys is provided.
- It uses Python stdlib plus macOS system tools (`security`, `openssl`).

Supported browsers:
- Firefox
- Chrome
- Chromium
- Brave
- Edge
- Vivaldi
- Opera
"""

from __future__ import annotations

import argparse
import glob
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from hashlib import pbkdf2_hmac, sha256
from pathlib import Path


PBKDF2_SALT = b"saltysalt"
PBKDF2_ITERATIONS = 1003
PBKDF2_KEY_LENGTH = 16
CHROME_CIPHER_PREFIXES = (b"v10", b"v11")
CHROME_IV_HEX = "20" * 16


@dataclass(frozen=True)
class ChromiumBrowser:
    name: str
    keychain_service: str
    root: Path


CHROMIUM_BROWSERS = (
    ChromiumBrowser(
        name="Chrome",
        keychain_service="Chrome Safe Storage",
        root=Path("~/Library/Application Support/Google/Chrome").expanduser(),
    ),
    ChromiumBrowser(
        name="Chromium",
        keychain_service="Chromium Safe Storage",
        root=Path("~/Library/Application Support/Chromium").expanduser(),
    ),
    ChromiumBrowser(
        name="Brave",
        keychain_service="Brave Safe Storage",
        root=Path("~/Library/Application Support/BraveSoftware/Brave-Browser").expanduser(),
    ),
    ChromiumBrowser(
        name="Edge",
        keychain_service="Microsoft Edge Safe Storage",
        root=Path("~/Library/Application Support/Microsoft Edge").expanduser(),
    ),
    ChromiumBrowser(
        name="Vivaldi",
        keychain_service="Vivaldi Safe Storage",
        root=Path("~/Library/Application Support/Vivaldi").expanduser(),
    ),
    ChromiumBrowser(
        name="Opera",
        keychain_service="Opera Safe Storage",
        root=Path("~/Library/Application Support/com.operasoftware.Opera").expanduser(),
    ),
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-d",
        "--domain-name",
        default="leetcode.com",
        help="Target domain, for example leetcode.com",
    )
    parser.add_argument(
        "-k",
        "--keys",
        default="",
        help="Comma-separated cookie names to print",
    )
    return parser.parse_args()


def iter_firefox_cookie_dbs() -> list[Path]:
    root = Path("~/Library/Application Support/Firefox/Profiles").expanduser()
    if not root.is_dir():
        return []
    candidates = []
    for profile in sorted(root.iterdir()):
        cookie_db = profile / "cookies.sqlite"
        if cookie_db.is_file():
            candidates.append(cookie_db)
    return candidates


def iter_chromium_cookie_dbs(root: Path) -> list[Path]:
    if not root.is_dir():
        return []

    candidates: list[Path] = []
    patterns = (
        "Cookies",
        "Default/Cookies",
        "Default/Network/Cookies",
        "Profile */Cookies",
        "Profile */Network/Cookies",
        "Guest Profile/Cookies",
        "Guest Profile/Network/Cookies",
    )
    for pattern in patterns:
        for match in glob.glob(str(root / pattern)):
            cookie_db = Path(match)
            if cookie_db.is_file():
                candidates.append(cookie_db)

    unique_candidates = []
    seen = set()
    for candidate in candidates:
        if candidate not in seen:
            seen.add(candidate)
            unique_candidates.append(candidate)
    return unique_candidates


def copied_db_path(db_path: Path) -> Path:
    tmp_dir = Path(tempfile.mkdtemp(prefix="leetcode-cookies-"))
    copied = tmp_dir / db_path.name
    shutil.copy2(db_path, copied)
    return copied


def query_firefox_cookies(db_path: Path, domain_name: str, keys: set[str]) -> dict[str, str]:
    copied = copied_db_path(db_path)
    try:
        conn = sqlite3.connect(str(copied))
        try:
            cursor = conn.execute(
                """
                SELECT name, value
                FROM moz_cookies
                WHERE host LIKE ?
                """,
                (f"%{domain_name}%",),
            )
            cookies = {}
            for name, value in cursor.fetchall():
                if keys and name not in keys:
                    continue
                cookies[name] = value
            return cookies
        finally:
            conn.close()
    finally:
        shutil.rmtree(copied.parent, ignore_errors=True)


def keychain_password(service_name: str) -> bytes:
    result = subprocess.run(
        ["security", "find-generic-password", "-w", "-s", service_name],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"unable to read {service_name}")
    return result.stdout.strip().encode("utf-8")


def chromium_key(service_name: str) -> bytes:
    secret = keychain_password(service_name)
    return pbkdf2_hmac(
        "sha1",
        secret,
        PBKDF2_SALT,
        PBKDF2_ITERATIONS,
        PBKDF2_KEY_LENGTH,
    )


def decrypt_chromium_value(encrypted_value: bytes, key: bytes, host_key: str) -> str:
    if not encrypted_value:
        return ""
    if not encrypted_value.startswith(CHROME_CIPHER_PREFIXES):
        return encrypted_value.decode("utf-8")

    payload = encrypted_value
    if payload.startswith(CHROME_CIPHER_PREFIXES):
        payload = payload[3:]

    result = subprocess.run(
        [
            "openssl",
            "enc",
            "-aes-128-cbc",
            "-d",
            "-nopad",
            "-nosalt",
            "-K",
            key.hex(),
            "-iv",
            CHROME_IV_HEX,
        ],
        input=payload,
        check=False,
        capture_output=True,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.decode("utf-8", errors="ignore").strip() or "openssl failed")

    plaintext = result.stdout
    if not plaintext:
        return ""
    padding = plaintext[-1]
    if 1 <= padding <= 16:
        plaintext = plaintext[:-padding]
    host_digest = sha256(host_key.encode("utf-8")).digest()
    if plaintext.startswith(host_digest):
        plaintext = plaintext[len(host_digest):]
    return plaintext.decode("utf-8")


def query_chromium_cookies(
    db_path: Path,
    domain_name: str,
    keys: set[str],
    service_name: str,
) -> dict[str, str]:
    copied = copied_db_path(db_path)
    try:
        conn = sqlite3.connect(str(copied))
        try:
            cursor = conn.execute(
                """
                SELECT host_key, name, value, encrypted_value
                FROM cookies
                WHERE host_key LIKE ?
                """,
                (f"%{domain_name}%",),
            )
            decrypted_key = None
            cookies = {}
            for host_key, name, value, encrypted_value in cursor.fetchall():
                if keys and name not in keys:
                    continue
                if value:
                    cookies[name] = value
                    continue
                if encrypted_value:
                    if decrypted_key is None:
                        decrypted_key = chromium_key(service_name)
                    cookies[name] = decrypt_chromium_value(
                        encrypted_value,
                        decrypted_key,
                        host_key,
                    )
            return cookies
        finally:
            conn.close()
    finally:
        shutil.rmtree(copied.parent, ignore_errors=True)


def print_cookies(cookies: dict[str, str], ordered_keys: list[str]) -> None:
    if ordered_keys:
        ordered_names = [name for name in ordered_keys if name in cookies]
    else:
        ordered_names = sorted(cookies)
    for name in ordered_names:
        value = cookies.get(name)
        if value is not None:
            print(name, value)


def try_firefox(domain_name: str, keys: set[str]) -> dict[str, str]:
    for db_path in iter_firefox_cookie_dbs():
        try:
            cookies = query_firefox_cookies(db_path, domain_name, keys)
            if cookies:
                return cookies
        except Exception as exc:  # pragma: no cover - operational diagnostics
            print(f"Get cookie from Firefox failed: {exc}", file=sys.stderr)
    return {}


def try_chromium(domain_name: str, keys: set[str]) -> dict[str, str]:
    for browser in CHROMIUM_BROWSERS:
        for db_path in iter_chromium_cookie_dbs(browser.root):
            try:
                cookies = query_chromium_cookies(
                    db_path,
                    domain_name,
                    keys,
                    browser.keychain_service,
                )
                if cookies:
                    return cookies
            except Exception as exc:  # pragma: no cover - operational diagnostics
                print(f"Get cookie from {browser.name} failed: {exc}", file=sys.stderr)
                continue
    return {}


def main() -> int:
    if sys.platform != "darwin":
        print("This vendored helper currently supports macOS only.", file=sys.stderr)
        return 1

    args = parse_args()
    ordered_keys = [key.strip() for key in args.keys.split(",") if key.strip()]
    requested_keys = set(ordered_keys)

    cookies = try_firefox(args.domain_name, requested_keys)
    if not cookies:
        cookies = try_chromium(args.domain_name, requested_keys)

    print_cookies(cookies, ordered_keys)
    return 0 if cookies else 1


if __name__ == "__main__":
    raise SystemExit(main())
