"""
Prompt injection detector.

Two-layer approach:
  Layer A — fast compiled-regex patterns covering direct attacks
  Layer B — normalisation pass to catch Unicode lookalike / base64 evasions,
             then re-run patterns on the normalised text
"""
import re
import base64
import unicodedata
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class InjectionResult:
    is_injection: bool
    matched_pattern: str | None
    confidence: float
    reason: str | None


# Common Unicode homoglyph → ASCII replacements
_HOMOGLYPHS: dict[str, str] = {
    "\u0456": "i",  # Cyrillic і
    "\u04CF": "i",  # Cyrillic ї
    "\u0430": "a",  # Cyrillic а
    "\u0435": "e",  # Cyrillic е
    "\u043E": "o",  # Cyrillic о
    "\u0440": "p",  # Cyrillic р
    "\u0441": "c",  # Cyrillic с
    "\u0445": "x",  # Cyrillic х
    "\u1D0F": "o",  # Latin letter small capital O
    "\u2139": "i",  # Information source ℹ
}

_HOMOGLYPH_TABLE = str.maketrans(_HOMOGLYPHS)


def _normalise(text: str) -> str:
    """
    1. NFKC normalisation collapses many Unicode variants.
    2. Replace known homoglyphs.
    3. Lower-case.
    """
    text = unicodedata.normalize("NFKC", text)
    text = text.translate(_HOMOGLYPH_TABLE)
    return text.lower()


def _try_decode_base64_fragments(text: str) -> str:
    """
    Find base64-looking tokens (≥16 chars, valid alphabet) and append
    their decoded form to the text so patterns can match them too.
    """
    extras: list[str] = []
    for token in re.findall(r"[A-Za-z0-9+/]{16,}={0,2}", text):
        try:
            decoded = base64.b64decode(token + "==").decode("utf-8", errors="ignore")
            if decoded.isprintable():
                extras.append(decoded)
        except Exception:
            pass
    return text + " " + " ".join(extras) if extras else text


_PATTERNS: list[tuple[str, str]] = [
    # instruction override
    (r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?", "instruction_override"),
    (r"disregard\s+(all\s+)?(previous|prior|above)\s+instructions?", "instruction_override"),
    (r"forget\s+(all\s+)?(previous|prior|above)\s+instructions?", "instruction_override"),
    (r"do\s+not\s+follow\s+(your\s+)?(previous|prior|original)\s+instructions?", "instruction_override"),

    # role hijacking
    (r"you\s+are\s+now\s+a", "role_hijack"),
    (r"act\s+as\s+(a\s+)?(different|new|another)", "role_hijack"),
    (r"pretend\s+(you\s+are|to\s+be)", "role_hijack"),
    (r"roleplay\s+as", "role_hijack"),
    (r"your\s+new\s+(role|persona|identity)\s+is", "role_hijack"),

    # system prompt extraction
    (r"(reveal|show|print|display)\s+(your\s+)?(system\s+prompt|instructions|context)", "prompt_extraction"),
    (r"what\s+(are\s+your|is\s+your)\s+(instructions|system\s+prompt)", "prompt_extraction"),
    (r"repeat\s+(everything|all)\s+(above|before)", "prompt_extraction"),
    (r"output\s+(your\s+)?(initial|full|complete)\s+(prompt|instructions)", "prompt_extraction"),

    # jailbreak
    (r"(do\s+anything\s+now|DAN)", "jailbreak"),
    (r"developer\s+mode", "jailbreak"),
    (r"\bjailbreak\b", "jailbreak"),
    (r"bypass\s+(your\s+)?(safety|filter|restriction|guideline)", "jailbreak"),
    (r"grandma\s+exploit", "jailbreak"),  # classic social-engineering framing

    # delimiter injection
    (r"```\s*system", "delimiter_injection"),
    (r"<\s*system\s*>", "delimiter_injection"),
    (r"\[INST\]|\[\/INST\]", "delimiter_injection"),
    (r"<\|im_start\|>", "delimiter_injection"),
    (r"###\s*system\s*:", "delimiter_injection"),

    # multilingual override attempts (common languages)
    (r"ignorez\s+toutes\s+les\s+instructions", "instruction_override"),   # French
    (r"ignora\s+todas\s+las\s+instrucciones", "instruction_override"),    # Spanish
    (r"ignoriere\s+alle\s+anweisungen", "instruction_override"),          # German
]

_COMPILED: list[tuple[re.Pattern, str]] = [
    (re.compile(p, re.IGNORECASE), label) for p, label in _PATTERNS
]


class InjectionDetector:
    def detect(self, text: str) -> InjectionResult:
        # Pass A — raw text
        result = self._scan(text)
        if result.is_injection:
            return result

        # Pass B — normalised + base64-decoded text
        normalised = _normalise(_try_decode_base64_fragments(text))
        return self._scan(normalised)

    def _scan(self, text: str) -> InjectionResult:
        for pattern, label in _COMPILED:
            match = pattern.search(text)
            if match:
                return InjectionResult(
                    is_injection=True,
                    matched_pattern=label,
                    confidence=0.95,
                    reason=f"Prompt injection detected: {label} — matched '{match.group()}'",
                )
        return InjectionResult(
            is_injection=False,
            matched_pattern=None,
            confidence=0.0,
            reason=None,
        )


# singleton
injection_detector = InjectionDetector()
