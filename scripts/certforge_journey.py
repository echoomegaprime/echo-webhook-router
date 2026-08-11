"""Critical journey for the ECHO Certification Forge.

The Forge runs this argv (declared as a top-level `journey` field in the
POST /v1/certifications request body -- NOT read from .echo/certification.json;
see [[reference-certification-forge-submit-recipe-20260810]] gotcha #8) inside
its isolated `python:3.12-alpine` sandbox, against the exact acquired commit,
with no network and no Node -- so the Worker itself cannot actually run, and
there is no `git` binary either (gotcha #9 of the same recipe). The full
behavioural suite (`npm test` -- typecheck plus the real signature/auth test
suite, run against the actual `src/index.ts` via Node's native TypeScript
support) runs in CI on this same commit; this journey proves the artifact the
Forge actually acquired is the intact, complete Worker source -- not that it
currently boots.

This repository is TypeScript-only (a single Cloudflare Worker, D1 + KV +
Analytics Engine, no framework); this journey therefore checks structural and
textual invariants rather than parsing Python.

Checks:
  1. The critical surfaces exist -- the Worker entrypoint, its test file, and
     the pinned Node dependency manifest.
  2. `src/index.ts` has not been truncated -- a cheap, tokenizer-free line and
     byte-size floor (a whole-text paren-balance count was tried on a sibling
     repo this campaign and false-positived against that file's regex
     literals; a size floor is more robust and this file has no such literals
     to worry about anyway).
  3. No install-lifecycle scripts have crept into `package.json`.
  4. No hardcoded secret-shaped literals in the acquired source.
  5. Every signature/token comparison still calls the constant-time
     `timingSafeEqual` rather than a raw `===`/`!==` -- functional tests
     can't distinguish a timing-safe comparison from a raw one (both return
     the same true/false), so this text-pattern check is the ONLY regression
     guard for that fix.
  6. The `hasSecret` reject-gate still covers all six secret-bearing sources
     (github, stripe, slack, telegram, whatsapp/messenger via META_APP_SECRET,
     vercel) -- the repo as found only enforced three of them, so a
     configured Telegram/WhatsApp/Messenger/Vercel secret was verified but
     never actually rejected on failure.
"""

from __future__ import annotations

import json
import pathlib
import re
import sys
from typing import NoReturn

CRITICAL_SURFACES = (
    "src/index.ts",
    "tests/auth.test.mjs",
    "package.json",
    "tsconfig.json",
)

INSTALL_LIFECYCLE_HOOKS = ("preinstall", "install", "postinstall", "prepare")

SECRET_LITERAL_PATTERN = re.compile(
    r'(?:api_key|secret|password|token)\s*=\s*["\'][a-zA-Z0-9_\-]{16,}["\']',
    re.IGNORECASE,
)

MIN_INDEX_TS_LINES = 900
MIN_INDEX_TS_BYTES = 25_000

# Every raw comparison this pass replaced. If any of these text patterns
# reappear, the corresponding fix regressed.
FORBIDDEN_RAW_COMPARISONS = (
    r"expected\s*===\s*signature",
    r"expected\s*===\s*sig\b",
    r"secretToken\s*===\s*expected",
    r"token\s*===\s*env\.WHATSAPP_VERIFY_TOKEN",
    r"apiKey\s*!==\s*env\.ECHO_API_KEY",
)

REQUIRED_HAS_SECRET_SOURCES = (
    "source === 'telegram' && env.TELEGRAM_WEBHOOK_SECRET",
    "(source === 'whatsapp' || source === 'messenger') && env.META_APP_SECRET",
    "source === 'vercel' && env.VERCEL_WEBHOOK_SECRET",
)


def _fail(message: str) -> NoReturn:
    print(f"ECHO_WEBHOOK_ROUTER_CRITICAL_JOURNEY_FAILED: {message}", file=sys.stderr)
    raise SystemExit(1)


def check_critical_surfaces() -> None:
    for surface in CRITICAL_SURFACES:
        if not pathlib.Path(surface).exists():
            _fail(f"missing critical surface: {surface}")


def _source_text() -> str:
    return pathlib.Path("src/index.ts").read_text(encoding="utf-8")


def check_index_ts_not_truncated() -> None:
    text = _source_text()
    line_count = text.count("\n") + 1
    byte_size = len(text.encode("utf-8"))
    if line_count < MIN_INDEX_TS_LINES:
        _fail(f"src/index.ts has only {line_count} lines (expected >= {MIN_INDEX_TS_LINES}) -- possible truncation")
    if byte_size < MIN_INDEX_TS_BYTES:
        _fail(f"src/index.ts is only {byte_size} bytes (expected >= {MIN_INDEX_TS_BYTES}) -- possible truncation")
    if "export default" not in text:
        _fail("src/index.ts is missing its 'export default' Worker entrypoint")


def check_no_install_hooks() -> None:
    manifest = pathlib.Path("package.json")
    try:
        scripts = json.loads(manifest.read_text(encoding="utf-8")).get("scripts", {})
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        _fail(f"package.json is not valid JSON: {exc}")
    present = sorted(hook for hook in INSTALL_LIFECYCLE_HOOKS if hook in scripts)
    if present:
        _fail(f"package.json reintroduced install-lifecycle script(s): {', '.join(present)}")


def check_no_hardcoded_secrets() -> None:
    match = SECRET_LITERAL_PATTERN.search(_source_text())
    if match:
        _fail(f"src/index.ts contains a hardcoded secret-shaped literal: {match.group(0)[:40]}...")


def check_constant_time_comparisons() -> None:
    text = _source_text()
    if "function timingSafeEqual(" not in text:
        _fail("timingSafeEqual() is missing entirely")
    for pattern in FORBIDDEN_RAW_COMPARISONS:
        if re.search(pattern, text):
            _fail(f"a raw comparison regressed back in: pattern '{pattern}' matched")
    # Every verify* function and the API-key check must call timingSafeEqual.
    call_count = len(re.findall(r"timingSafeEqual\(", text))
    if call_count < 8:  # 6 verify* signature checks + WHATSAPP_VERIFY_TOKEN + API key
        _fail(f"expected >= 8 timingSafeEqual( call sites, found {call_count} -- a comparison may have regressed")


def check_has_secret_gate_complete() -> None:
    text = _source_text()
    for fragment in REQUIRED_HAS_SECRET_SOURCES:
        if fragment not in text:
            _fail(
                f"the hasSecret reject-gate is missing coverage for: {fragment!r} -- this reintroduces "
                f"the original defect where a configured secret for telegram/whatsapp/messenger/vercel "
                f"was verified but never enforced"
            )


def main() -> None:
    check_critical_surfaces()
    check_index_ts_not_truncated()
    check_no_install_hooks()
    check_no_hardcoded_secrets()
    check_constant_time_comparisons()
    check_has_secret_gate_complete()
    print(
        "ECHO_WEBHOOK_ROUTER_CRITICAL_JOURNEY_OK "
        "critical_surfaces=4 install_hooks=0 hardcoded_secrets=0 "
        "constant_time_comparisons=1 has_secret_gate_complete=1"
    )


if __name__ == "__main__":
    main()
