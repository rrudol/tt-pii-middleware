#!/usr/bin/env python3
"""Evaluate the PII engine against a gold JSONL corpus.

Matching policy (exact span):
  TP  = predicted (start, end, label) exactly equals a gold entity
  FP  = predicted span with no exact gold match
  FN  = gold entity with no exact predicted match

Checksum-backed labels additionally report *invalid-ID false positives*
when a predicted span's text fails the corresponding validator.

Usage::

    python scripts/eval_corpus.py data/synthetic/pl_pii_v1.jsonl \\
        --out eval/results/latest.json --fail-under eval/gates_mvp.json
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from pii_core import is_valid_iban, is_valid_luhn, is_valid_nip, is_valid_pesel, is_valid_regon

from tt_pii_middleware.analyzer import PiiEngine
from tt_pii_middleware.config import Settings
from tt_pii_middleware.recognizers import is_valid_dowod

# Labels where a predicted value MUST pass a checksum; FPs on invalids are fatal.
CHECKSUM_VALIDATORS = {
    "PESEL": is_valid_pesel,
    "NIP": lambda s: is_valid_nip(s.replace("-", "").replace(" ", "")),
    "REGON": is_valid_regon,
    "IBAN": lambda s: is_valid_iban(s.replace(" ", "")),
    "CARD": lambda s: is_valid_luhn(s.replace(" ", "")),
    "DOWOD": is_valid_dowod,
}


@dataclass
class LabelStats:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    invalid_fp: int = 0  # predicted checksum-label whose text fails validation

    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 1.0

    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 1.0

    def f1(self) -> float:
        p, r = self.precision(), self.recall()
        return 2 * p * r / (p + r) if (p + r) else 0.0

    def as_dict(self) -> dict:
        return {
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "invalid_fp": self.invalid_fp,
            "precision": round(self.precision(), 4),
            "recall": round(self.recall(), 4),
            "f1": round(self.f1(), 4),
            "support": self.tp + self.fn,
        }


@dataclass
class EvalResult:
    n_docs: int = 0
    total_ms: float = 0.0
    by_label: dict[str, LabelStats] = field(default_factory=lambda: defaultdict(LabelStats))
    # Predictions on labels that have no gold in the doc still count as FP under that label.
    micro: LabelStats = field(default_factory=LabelStats)

    def finalize(self) -> dict:
        per = {k: v.as_dict() for k, v in sorted(self.by_label.items())}
        return {
            "n_docs": self.n_docs,
            "avg_ms_per_doc": round(self.total_ms / max(self.n_docs, 1), 2),
            "micro": self.micro.as_dict(),
            "per_label": per,
        }


def _key(start: int, end: int, label: str) -> tuple[int, int, str]:
    return (start, end, label)


def evaluate_doc(
    engine: PiiEngine,
    doc: dict,
    result: EvalResult,
    scored_labels: set[str] | None,
) -> None:
    t0 = time.perf_counter()
    preds = engine.analyze(doc["text"], language=doc.get("language") or "pl")
    result.total_ms += (time.perf_counter() - t0) * 1000

    gold_list = doc.get("entities") or []
    if scored_labels is not None:
        gold_list = [g for g in gold_list if g["label"] in scored_labels]

    gold_keys = {_key(g["start"], g["end"], g["label"]) for g in gold_list}
    pred_keys: set[tuple[int, int, str]] = set()
    for p in preds:
        if scored_labels is not None and p.label not in scored_labels:
            continue
        pred_keys.add(_key(p.start, p.end, p.label))
        # Invalid checksum FP tracking (independent of gold match).
        validator = CHECKSUM_VALIDATORS.get(p.label)
        if validator is not None and not validator(p.text):
            result.by_label[p.label].invalid_fp += 1

    matched = gold_keys & pred_keys
    fps = pred_keys - gold_keys
    fns = gold_keys - pred_keys

    for start, end, label in matched:
        result.by_label[label].tp += 1
        result.micro.tp += 1
    for start, end, label in fps:
        result.by_label[label].fp += 1
        result.micro.fp += 1
    for start, end, label in fns:
        result.by_label[label].fn += 1
        result.micro.fn += 1


def load_jsonl(path: Path) -> list[dict]:
    docs = []
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                docs.append(json.loads(line))
    return docs


def check_gates(report: dict, gates: dict) -> list[str]:
    """Return list of human-readable failure messages (empty = pass)."""
    failures: list[str] = []
    micro_gate = gates.get("micro_f1")
    if micro_gate is not None and report["micro"]["f1"] < micro_gate:
        failures.append(
            f"micro F1 {report['micro']['f1']:.4f} < gate {micro_gate}"
        )

    per = report["per_label"]
    for label, req in (gates.get("labels") or {}).items():
        stats = per.get(label)
        if stats is None:
            # Label absent from both gold and preds — treat as perfect if support was 0,
            # but fail if the gate demanded a minimum support.
            if req.get("min_support", 0) > 0:
                failures.append(f"{label}: missing from report (need support >= {req['min_support']})")
            continue
        if stats["support"] < req.get("min_support", 0):
            failures.append(
                f"{label}: support {stats['support']} < min_support {req['min_support']}"
            )
        for metric in ("f1", "precision", "recall"):
            floor = req.get(metric)
            if floor is not None and stats[metric] < floor:
                failures.append(
                    f"{label}: {metric} {stats[metric]:.4f} < gate {floor}"
                )
        if req.get("max_invalid_fp") is not None and stats["invalid_fp"] > req["max_invalid_fp"]:
            failures.append(
                f"{label}: invalid_fp {stats['invalid_fp']} > max {req['max_invalid_fp']}"
            )
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", type=Path)
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument(
        "--fail-under",
        type=Path,
        default=None,
        help="JSON gate file; exit 1 if any gate fails",
    )
    parser.add_argument(
        "--labels",
        default=None,
        help="Comma-separated TT labels to score (default: all)",
    )
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--enable-krs", action="store_true", default=True)
    args = parser.parse_args()

    docs = load_jsonl(args.corpus)
    if args.limit:
        docs = docs[: args.limit]

    scored = set(args.labels.split(",")) if args.labels else None
    engine = PiiEngine(Settings(enable_krs=args.enable_krs, redis_url=None))

    result = EvalResult()
    for doc in docs:
        result.n_docs += 1
        evaluate_doc(engine, doc, result, scored)

    report = result.finalize()
    report["corpus"] = str(args.corpus)
    text = json.dumps(report, ensure_ascii=False, indent=2)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text + "\n", encoding="utf-8")
        print(f"wrote {args.out}")
    print(text)

    if args.fail_under:
        gates = json.loads(args.fail_under.read_text(encoding="utf-8"))
        failures = check_gates(report, gates)
        if failures:
            print("GATE FAILURES:", file=sys.stderr)
            for f in failures:
                print(f"  - {f}", file=sys.stderr)
            return 1
        print("all gates passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
