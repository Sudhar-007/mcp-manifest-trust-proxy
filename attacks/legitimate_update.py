"""Not an attack: an honest maintainer rewording calc's `add` description.

The point of this script is the negative case. It changes the description
text, so pinning still reports DRIFT and suspends the tool -- but neither
detector fires, so it classifies as COSMETIC, nothing is quarantined, and the
console's Approve button is enabled. That is what stops the guard from being a
blunt instrument: a typo fix must be approvable in one click, while an
injected instruction must not be approvable at all.

    python attacks/legitimate_update.py            apply
    python attacks/legitimate_update.py --restore  undo
"""

import argparse
import sys
from pathlib import Path

TARGET = Path(__file__).resolve().parent.parent / "servers" / "calc_server.py"

ORIGINAL = '    """Add two integers and return the sum."""\n'

UPDATED = '    """Add two integers and return their sum as a plain integer."""\n'


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--restore", action="store_true", help="undo the update")
    args = parser.parse_args()

    with open(TARGET, encoding="utf-8", newline="") as file:
        source = file.read()
    newline = "\r\n" if "\r\n" in source else "\n"
    original, updated = ORIGINAL.replace("\n", newline), UPDATED.replace("\n", newline)
    old, new = (updated, original) if args.restore else (original, updated)

    if new in source:
        print(f"{TARGET.name}: already {'restored' if args.restore else 'updated'}; nothing to do.")
        return 0
    if old not in source:
        print(f"{TARGET.name}: expected `add` docstring not found; restore other attacks first.", file=sys.stderr)
        return 1

    with open(TARGET, "w", encoding="utf-8", newline="") as file:
        file.write(source.replace(old, new, 1))

    if args.restore:
        print(f"{TARGET.name}: `add` description restored.")
    else:
        print(f"{TARGET.name}: `add` description reworded. No injection, no cross-server reference.")
        print("Expect DRIFT -> suspended, classified COSMETIC, and an enabled Approve button.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
