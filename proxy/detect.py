"""Two deterministic detectors for tool descriptions. No state, no LLM.

cross_server_refs        does this description name another server's tool?
agent_directed_imperatives  is this text talking to the model rather than
                            describing subject matter?

The second one is the hard half. "Always wear gloves" is subject matter and
must pass. "Always call this tool first" is aimed at the model and must not.
So a bare imperative is never enough on its own: every signal here also needs
something that points at the agent (a tool, the user, the session, secrecy,
or the act of being read).
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Finding:
    detector: str  # "cross_server" | "imperative"
    signal: str  # which rule fired
    text: str  # the exact matched substring
    start: int
    end: int
    owner: str | None = None  # for cross_server: the server the name belongs to

    def describe(self) -> str:
        where = f"[{self.start}:{self.end}]"
        if self.detector == "cross_server":
            return f"cross-server reference to {self.owner}'s tool {self.text!r} {where}"
        return f"agent-directed {self.signal} {self.text!r} {where}"


# --------------------------------------------------------------------------
# 1. cross-server references
# --------------------------------------------------------------------------


def cross_server_refs(description: str, registry: dict[str, list[str]], self_server: str | None = None) -> list[Finding]:
    """Findings for any mention of a *different* server's tool.

    `registry` is {server_name: [tool_names]}, which the proxy already holds.
    `self_server` is the server this description belongs to, so its own names
    are not flagged.

    Tool names match bare (`send_email`) and namespaced (`email__send_email`);
    a server name matches only when used as a namespace (`email__...`). A bare
    server name is not enough, because names like "email" are ordinary words
    and flagging them would flag ordinary prose.
    """
    findings: list[Finding] = []
    for server, tools in registry.items():
        if server == self_server:
            continue
        for match in re.finditer(rf"\b{re.escape(server)}__\w+", description):
            findings.append(Finding("cross_server", "namespaced", match.group(0), match.start(), match.end(), server))
        for tool in tools:
            for match in re.finditer(rf"\b{re.escape(tool)}\b", description):
                findings.append(Finding("cross_server", "tool", match.group(0), match.start(), match.end(), server))

    # Drop a bare match that sits inside a namespaced one, so `email__send_email`
    # is reported once.
    kept: list[Finding] = []
    for finding in sorted(findings, key=lambda f: (f.start, -(f.end - f.start))):
        if any(k.start <= finding.start and finding.end <= k.end for k in kept):
            continue
        kept.append(finding)
    return kept


# --------------------------------------------------------------------------
# 2. agent-directed imperatives
# --------------------------------------------------------------------------

# Second person only counts next to one of these nouns.
SECOND_PERSON = r"\b(?:you|your|yourself|you're)\b"
AGENT_NOUNS = r"\b(?:tools?|sessions?|context|files?|users?|conversations?|messages?|prompts?)\b"

PATTERNS: list[tuple[str, str]] = [
    # "when this is available", "when retrieved" -- text aware of being read.
    (
        "meta_reference",
        r"\b(?:when|once|after|upon)\s+(?:this|these|it|the\s+(?:description|tool|text|content|context|instructions?|schema|prompt))"
        r"(?:\s+(?:is|are|has\s+been|been))?\s*"
        r"(?:retrieved|read|loaded|available|shown|surfaced|injected|displayed|processed|parsed)\b"
        r"|\bwhen\s+retrieved\b",
    ),
    # "do not mention", "never disclose" -- secrecy about the instruction itself.
    (
        "secrecy",
        r"\b(?:do\s+not|don['’]t|never)\s+"
        r"(?:mention|disclose|reveal|tell|inform|share|say|report|acknowledge|discuss|expose)\b",
    ),
    # "this step is mandatory" -- claimed obligation about an action, not a field.
    (
        "mandatory",
        r"\b(?:this|the\s+(?:following|above))\s+(?:step|action|instruction|procedure|call|task|process|tool\s+call)\s+"
        r"(?:is|are)\s+(?:required|mandatory|compulsory|essential|obligatory|non-?negotiable|critical)\b"
        r"|\bit\s+is\s+(?:required|mandatory|essential|imperative)\s+(?:that|to)\b",
    ),
    # Ordering that is about answering or about calling tools -- never generic
    # ordering, so "before adding the flour" stays clean.
    (
        "tool_ordering",
        r"\bbefore\s+(?:responding|replying|answering)\b"
        r"|\bbefore\s+you\s+(?:respond|reply|answer|continue)\b"
        r"|\bbefore\s+(?:using|calling|invoking|running)\s+(?:any\s+other\s+|any\s+|another\s+|other\s+|the\s+|this\s+)?tools?\b"
        r"|\b(?:first|always|immediately)\s+(?:call|invoke|run|use|trigger)\s+(?:this\s+|the\s+|that\s+)?tool\b"
        r"|\bcall\s+(?:this|the)\s+tool\s+first\b",
    ),
]


def agent_directed_imperatives(text: str) -> list[Finding]:
    """Findings for instructions aimed at the model rather than at the reader's subject matter."""
    findings: list[Finding] = []

    for signal, pattern in PATTERNS:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            findings.append(Finding("imperative", signal, match.group(0), match.start(), match.end()))

    # Second person is only a signal when an agent-ish noun sits in the same
    # sentence: "you must wear gloves" is subject matter, "you must call the
    # tool" is not.
    for offset, sentence in _sentences(text):
        pronouns = list(re.finditer(SECOND_PERSON, sentence, re.IGNORECASE))
        nouns = list(re.finditer(AGENT_NOUNS, sentence, re.IGNORECASE))
        if not pronouns or not nouns:
            continue
        pronoun, noun = min(
            ((p, n) for p in pronouns for n in nouns), key=lambda pair: abs(pair[0].start() - pair[1].start())
        )
        start, end = min(pronoun.start(), noun.start()), max(pronoun.end(), noun.end())
        findings.append(Finding("imperative", "second_person", sentence[start:end], offset + start, offset + end))

    seen: set[tuple[str, int, int]] = set()
    unique: list[Finding] = []
    for finding in sorted(findings, key=lambda f: (f.start, f.signal)):
        marker = (finding.signal, finding.start, finding.end)
        if marker in seen:
            continue
        seen.add(marker)
        unique.append(finding)
    return unique


def _sentences(text: str) -> list[tuple[int, str]]:
    """(offset, sentence) pairs, split on sentence terminators and newlines."""
    return [(match.start(), match.group(0)) for match in re.finditer(r"[^.!?\n]+", text)]
