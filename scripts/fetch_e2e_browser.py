"""Download the pinned Chrome for Testing build the end-to-end tests run against.

Prints the path of the Chrome binary, ready for ``DBSC_E2E_BROWSER``::

    export DBSC_E2E_BROWSER="$(uv run python scripts/fetch_e2e_browser.py)"
    uv run pytest -m e2e

Why a pinned build: DBSC on Linux needs Chromium's software-key testing switch
(``EnableBoundSessionCredentialsSoftwareKeysForManualTesting``), and that is version-sensitive.
Chrome 149 and 150 honour it; Chromium 153 (Playwright 1.63's bundled build) silently ignores
the registration header. Bump CHROME_VERSION only after the e2e suite passes on the new build.

Linux x86-64 only, like the CI runner. Stdlib only.
"""

import argparse
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


def fetch(dest: Path) -> Path:
    """Download and unpack the pinned build under ``dest`` (once); return the binary path."""
    root = dest / CHROME_VERSION
    binary = root / "chrome-linux64" / "chrome"
    if binary.is_file():
        return binary

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
