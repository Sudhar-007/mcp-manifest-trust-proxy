"""Driver for the full demo. Calls what already exists; adds no behaviour.

Each scene restores the previous scene's script before applying its own, so
the scenes never stack. Between scenes it waits for Enter, so the pace is
yours while you talk.

    python demo.py             the whole sequence, scene 0 to 6
    python demo.py --reset     scene 0 only, to re-arm between rehearsals
    python demo.py --scene 4   reset, pin a clean baseline, then play one scene
    python demo.py --no-pause  no keypresses, for a dry run

A scene from 2 onwards is a change to an *already approved* server, so a jump
pins a clean baseline first. Without that the attack would be pinned as the
baseline and read as CLEAN instead of DRIFT.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PYTHON = sys.executable
CONSOLE_URL = "http://127.0.0.1:8765"

ATTACKS = ["legitimate_update", "rug_pull", "tool_shadowing", "tool_poisoning", "poisoned_document"]

# (title, script to apply or None, what to watch for)
SCENES: list[tuple[str, str | None, str]] = [
    ("Reset and first run", None, "FIRST_RUN: three servers pinned, every tool active"),
    ("Clean reconnect", None, "CLEAN: live roots match the signed pins, nothing blocked"),
    ("Rug pull", "rug_pull", "DRIFT -> suspended, diff shown; neither detector fires"),
    ("Tool shadowing", "tool_shadowing", "CROSS_SERVER: calc's description names email's send_email"),
    ("Tool poisoning", "tool_poisoning", "INSTRUCTION: quarantined, hidden from the client"),
    ("Poisoned document", "poisoned_document", "manifest CLEAN; only the output firewall sees it"),
    ("A legitimate update", "legitimate_update", "DRIFT -> COSMETIC, no findings, Approve enabled"),
]


class SceneFailed(Exception):
    def __init__(self, scene: int, command: list[str], code: int) -> None:
        super().__init__(f"scene {scene} failed (exit {code}): {' '.join(command)}")
        self.scene = scene
        self.command = command
        self.code = code


def run(command: list[str], scene: int, *, tolerant: bool = False) -> str:
    """Run a subprocess, capturing output. Any non-zero exit stops the demo.

    `tolerant` is only for the first reset pass, where a restore is *expected*
    to fail; see reset().
    """
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
    output = (result.stdout or "") + (result.stderr or "")
    if result.returncode != 0 and not tolerant:
        sys.stdout.write(output)
        raise SceneFailed(scene, command, result.returncode)
    return output


def attack(name: str, scene: int, *, restore: bool = False, tolerant: bool = False) -> None:
    command = [PYTHON, str(ROOT / "attacks" / f"{name}.py")]
    if restore:
        command.append("--restore")
    run(command, scene, tolerant=tolerant)  # output discarded: the banner belongs on screen


def demo_client(scene: int) -> str:
    return run([PYTHON, "-m", "proxy.demo_client"], scene)


def reset(scene: int = 0) -> None:
    """Clear the trust store and put every attacked file back.

    Two passes, because several scripts edit the same `add` docstring. A
    restore whose own payload is not present cannot find its anchor and exits
    non-zero -- so if rug_pull is the one applied, legitimate_update's restore
    fails first and would abort the reset before rug_pull's ever ran.

    Pass 1 therefore ignores exit codes: whichever attack is actually applied
    is undone by its own script, and the rest are harmless no-ops. Pass 2 runs
    strict, so every script must now report "already restored". That proves the
    tree is clean using each attack's own knowledge of its payload, rather than
    duplicating the payload text here.
    """
    for path in (ROOT / "proxy" / "trust.db", ROOT / "proxy" / ".trust_key"):
        path.unlink(missing_ok=True)
    for name in ATTACKS:
        attack(name, scene, restore=True, tolerant=True)
    for name in ATTACKS:
        attack(name, scene, restore=True)  # strict: verifies the tree really is clean


def banner(number: int, title: str) -> None:
    print()
    print("=" * 72)
    print(f"SCENE {number}. {title}")
    print("=" * 72)


def verdicts(output: str) -> list[str]:
    """The trust lines worth reading aloud, in the order the proxy logged them."""
    keep = []
    for line in output.splitlines():
        if "[trust" not in line:
            continue
        text = line.split("]", 1)[-1].strip()
        if any(mark in text for mark in ("FIRST_RUN", "CLEAN", "DRIFT", "TAMPERED", "QUARANTINED", "output wrapped")):
            keep.append(text)
    return keep


def wait(pause: bool) -> None:
    if not pause:
        return
    try:
        input("\n  [Enter] for the next scene ")
    except EOFError:  # stdin is not interactive after all; just keep going
        print()


def play(number: int, pause: bool) -> None:
    title, script, expect = SCENES[number]
    banner(number, title)
    print(f"  expect: {expect}")
    if script is not None:
        print(f"  applying attacks/{script}.py")
        attack(script, number)
    print("  running the demo client ...")
    output = demo_client(number)
    print()
    for line in verdicts(output):
        print(f"  | {line}")
    wait(pause)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--reset", action="store_true", help="scene 0 only, then exit")
    parser.add_argument("--scene", type=int, metavar="N", help=f"reset, then play only scene 0-{len(SCENES) - 1}")
    parser.add_argument("--no-pause", action="store_true", help="do not wait for a keypress between scenes")
    args = parser.parse_args()

    if args.scene is not None and not 0 <= args.scene < len(SCENES):
        print(f"--scene must be 0..{len(SCENES) - 1}", file=sys.stderr)
        return 2

    pause = not args.no_pause
    print(f"MCP trust proxy demo. Console: {CONSOLE_URL}")
    print("Start it first in another terminal:  python -m console.app")

    try:
        reset()
        if args.reset:
            print("\nReset done: trust store cleared, all five scripts restored.")
            return 0

        if args.scene is not None:
            if args.scene >= 2:
                # Approve the clean manifest first, so the scene reads as DRIFT.
                print("\n  pinning a clean baseline first ...")
                demo_client(args.scene)
            play(args.scene, pause=False)
            return 0

        previous: str | None = None
        for number in range(len(SCENES)):
            if previous is not None:
                attack(previous, number, restore=True)
            play(number, pause=pause and number < len(SCENES) - 1)
            previous = SCENES[number][1]
    except SceneFailed as failure:
        print(f"\nSTOPPED. {failure}", file=sys.stderr)
        return 1

    print("\nDemo complete. Run `python demo.py --reset` to re-arm.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
