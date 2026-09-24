"""Download the pinned Chrome for Testing build the end-to-end tests run against.

Prints the path of the Chrome binary, ready for ``DBSC_E2E_BROWSER``::

    export DBSC_E2E_BROWSER="$(uv run python scripts/fetch_e2e_browser.py)"
    uv run pytest -m e2e

Why a pinned build: DBSC on Linux needs Chromium's software-key testing switch
(``EnableBoundSessionCredentialsSoftwareKeysForManualTesting``), and newer Chrome no longer
honours it for standard DBSC. Chrome 149 and 150 register sessions with it. Tested on
2026-09-24, every current channel (Stable 154, Beta 155, Dev and Canary 156) silently ignores
the registration header. That holds even with ``chrome://flags`` set to "Device Bound Session
Credentials (Standard): Enabled - For developers", over http and https, headless and headed.
Bump CHROME_VERSION only after the e2e suite passes on the new build.

Linux x86-64 only, like the CI runner. Stdlib only.
"""

import argparse
import re
import shutil
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path

CHROME_VERSION = "149.0.7827.55"
URL = (
    "https://storage.googleapis.com/chrome-for-testing-public/"
    f"{CHROME_VERSION}/linux64/chrome-linux64.zip"
)
DEFAULT_DEST = Path(__file__).resolve().parent.parent / ".cache" / "e2e-browser"
_VERSION = re.compile(r"[0-9]+(?:\.[0-9]+){3}")


def fetch(dest: Path) -> Path:
    """Download and unpack the pinned build under ``dest`` (once); return the binary path.

    Other versions cached under ``dest`` are removed once the pinned one is in place.
    """
    root = dest / CHROME_VERSION
    binary = root / "chrome-linux64" / "chrome"
    if not binary.is_file():
        root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryFile() as archive:
            print(f"Downloading Chrome for Testing {CHROME_VERSION} ...", file=sys.stderr)
            with urllib.request.urlopen(URL, timeout=60) as response:  # noqa: S310 (pinned https URL)
                shutil.copyfileobj(response, archive)
            archive.seek(0)
            with zipfile.ZipFile(archive) as zf:
                for info in zf.infolist():
                    extracted = Path(zf.extract(info, root))
                    # zipfile drops Unix permissions; restore them so chrome and its helpers run.
                    if mode := info.external_attr >> 16:
                        extracted.chmod(mode & 0o7777)
        if not binary.is_file():
            raise SystemExit(f"Download did not contain {binary.relative_to(root)}")

    for old in dest.iterdir():
        if old.is_dir() and old.name != CHROME_VERSION and _VERSION.fullmatch(old.name):
            shutil.rmtree(old)
    return binary


def main() -> None:
    """CLI entry point: fetch (if needed) and print the binary path."""
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--dest", type=Path, default=DEFAULT_DEST, help="download directory")
    args = parser.parse_args()
    if sys.platform != "linux":
        raise SystemExit("The pinned e2e browser is only fetched for Linux x86-64.")
    print(fetch(args.dest))


if __name__ == "__main__":
    main()
