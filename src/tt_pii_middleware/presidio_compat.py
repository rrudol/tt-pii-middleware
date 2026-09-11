"""Presidio HTTP shape used by Bifrost guardrails (`type=presidio`).

Microsoft Presidio analyzer/anonymizer speak:

* ``POST /analyze`` → JSON **array** of ``{entity_type, start, end, score}``
* ``POST /anonymize`` → ``{text, items}``

This module maps that wire format onto the TT engine (TT labels such as
PESEL/NIP/EMAIL, not Presidio's ``PL_PESEL`` / ``EMAIL_ADDRESS``). Incoming
entity filters accept either family of names.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from tt_pii_middleware.analyzer import PRESIDIO_TO_TT, TT_LABELS, Span

# Bifrost UI chips and stock Presidio entity names → TT labels.
_INCOMING_TO_TT: dict[str, str] = {label: label for label in TT_LABELS}
_INCOMING_TO_TT.update(PRESIDIO_TO_TT)


class PresidioAnalyzeRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    text: str
    language: str | None = None
    entities: list[str] | None = None
    score_threshold: float | None = Field(default=None, ge=0.0, le=1.0)


class PresidioAnalyzerResult(BaseModel):
    model_config = ConfigDict(extra="ignore")

    entity_type: str
    start: int
    end: int
    score: float = 0.0


class PresidioAnonymizeRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    text: str
    analyzer_results: list[PresidioAnalyzerResult] = Field(default_factory=list)


def coerce_language(language: str | None, default: str = "pl") -> str:
    """Presidio sends free-form language tags; the engine only has pl/en."""
    if not language:
        return default
    lowered = language.split("-", 1)[0].strip().lower()
    if lowered in {"pl", "en"}:
        return lowered
    return default


def incoming_to_tt(entity: str) -> str | None:
    return _INCOMING_TO_TT.get(entity)


def map_incoming_entities(entities: list[str] | None) -> list[str] | None:
    """Translate a Presidio/TT entity allow-list to TT labels.

    ``None`` / empty means "detect everything". A non-empty list that maps
    to nothing means "detect nothing" (do not silently widen the filter).
    """
    if not entities:
        return None
    mapped: list[str] = []
    seen: set[str] = set()
    for entity in entities:
        label = incoming_to_tt(entity)
        if label and label not in seen:
            seen.add(label)
            mapped.append(label)
    return mapped


def spans_to_presidio(spans: list[Span]) -> list[dict[str, Any]]:
    return [
        {
            "entity_type": span.label,
            "start": span.start,
            "end": span.end,
            "score": span.score,
        }
        for span in spans
    ]


def apply_analyzer_results(text: str, results: list[PresidioAnalyzerResult]) -> dict[str, Any]:
    """Replace the given spans with ``<LABEL>`` (Presidio default operator)."""
    ordered = sorted(results, key=lambda item: item.start, reverse=True)
    out = text
    items: list[dict[str, Any]] = []
    for item in ordered:
        if item.start < 0 or item.end > len(out) or item.start >= item.end:
            continue
        label = incoming_to_tt(item.entity_type) or item.entity_type
        replacement = f"<{label}>"
        out = out[: item.start] + replacement + out[item.end :]
        items.append(
            {
                "operator": "replace",
                "entity_type": label,
                "start": item.start,
                "end": item.start + len(replacement),
            }
        )
    items.reverse()
    return {"text": out, "items": items}
