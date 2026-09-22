# SPDX-License-Identifier: Apache-2.0
"""Compare test ordering using saved outcomes only. Executes no tests or code edits.

This is a retrospective scheduling exercise, not a reproduction of Dream-RSI.
Full validation remains mandatory regardless of the suggested diagnostic order.
"""
from pathlib import Path
import hashlib
import json


def replay(directory):
    history = json.loads((directory / "rounds.json").read_text())
    rounds = history["rounds"]
    if history.get("schema") != 1 or not rounds:
        raise ValueError("unsupported or empty history")
    tests = {item["test"] for item in rounds[0]["outcomes"]}
    evaluator = rounds[0]["evaluator_sha256"]
    prior_failures = set()
    comparisons = []
    for index, record in enumerate(rounds):
        if record["evaluator_sha256"] != evaluator:
            raise ValueError("changed evaluator: results cannot be compared as one experiment")
        rows = record["outcomes"]
        if len(rows) != len(tests) or {row["test"] for row in rows} != tests:
            raise ValueError("changed or duplicate test population")
        if any(row["outcome"] not in ("pass", "fail") for row in rows):
            raise ValueError("missing outcomes are unknown, not passes")
        log = Path(record["log"])
        if log.name != str(log):
            raise ValueError("logs must be adjacent named files")
        if hashlib.sha256((directory / log).read_bytes()).hexdigest() != record["log_sha256"]:
            raise ValueError("recorded log hash mismatch")
        # Orders see previous rounds only; this round's outcomes are revealed
        # one at a time below, after each test has been selected.
        orders = {
            "alphabetical": sorted(tests),
            "previous_failures_first": sorted(tests, key=lambda t: (t not in prior_failures, t)),
            "cleanup_first": sorted(tests, key=lambda t: (not any(x in t for x in ("test_len_", "test_stats_")), t)),
        }
        outcomes = {row["test"]: row["outcome"] for row in rows}
        if index:
            scores = {}
            for name, order in orders.items():
                for count, test in enumerate(order, 1):
                    if outcomes[test] == "fail":
                        break
                scores[name] = {"checks_until_failure_or_exhaustion": count,
                                "failure_observed": any(outcomes[t] == "fail" for t in order[:count])}
            comparisons.append({"candidate": record["candidate"], "orders": scores})
        prior_failures = {test for test, outcome in outcomes.items() if outcome == "fail"}
    totals = {name: sum(row["orders"][name]["checks_until_failure_or_exhaustion"] for row in comparisons)
              for name in ("alphabetical", "previous_failures_first", "cleanup_first")}
    winner = min(totals, key=totals.get)
    return {"schema": 1, "comparisons": comparisons, "total_diagnostic_checks": totals,
            "recommendation": winner if totals[winner] < totals["alphabetical"] else "keep_alphabetical_no_observed_gain",
            "new_experiments_executed": 0, "automatic_promotion": False,
            "limitation": "Retrospective, tiny recorded corpus. Candidate evaluation actually ran every test. No measured compute saving or generalization claim."}


if __name__ == "__main__":
    print(json.dumps(replay(Path(__file__).resolve().parent), indent=2))
