from __future__ import annotations

import sys
from typing import Any, Dict

from backend.analysis import AnalysisResult, analyze_results
from backend.backend import analyze_scan_results

def _build_sample_results() -> Dict[str, Any]:

    return {
        "start_url": "https://example.com",
        "standards": ["GDPR"],
        "pages": {
            "domain_findings": {},
            "https://example.com/": {
                "security_headers": {
                    "findings": [
                        ("high", "Missing X-Frame-Options header"),
                    ]
                },
                "cookies": {
                    "findings": [
                        ("low", "Session cookie missing HttpOnly flag"),
                    ]
                },
            },
        },
    }

def test_analyze_results_empty() -> bool:
    print("\n" + "=" * 70)
    print("BACKEND TEST 1: analyze_results on empty results")
    print("=" * 70)

    results: Dict[str, Any] = {}
    analysis = analyze_results(results)

    assert isinstance(analysis, AnalysisResult), "Expected AnalysisResult instance"
    assert analysis.findings == [], "Expected no findings for empty input"
    assert analysis.summary_counts == {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }, "Unexpected summary counts for empty input"
    assert 0 <= analysis.score <= 100, "Score should be within 0..100"

    print("✅ PASS: analyze_results handles empty input correctly")
    return True

def test_analyze_results_sample_data() -> bool:
    print("\n" + "=" * 70)
    print("BACKEND TEST 2: analyze_results on sample findings")
    print("=" * 70)

    results = _build_sample_results()
    analysis = analyze_results(results)

    assert isinstance(analysis, AnalysisResult), "Expected AnalysisResult instance"
    assert len(analysis.findings) == 2, "Expected two findings from sample data"

    severities = [f.severity.lower() for f in analysis.findings]
    assert severities == ["high", "low"], "Findings should be sorted by severity"

    expected_counts = {"critical": 0, "high": 1, "medium": 0, "low": 1}
    assert (
        analysis.summary_counts == expected_counts
    ), f"Unexpected summary counts: {analysis.summary_counts!r}"

    assert (
        analysis.score == 88
    ), f"Unexpected score {analysis.score!r}, expected 88 for sample data"

    print("✅ PASS: analyze_results aggregates, sorts and scores sample data correctly")
    return True

def test_analyze_scan_results_wrapper() -> bool:
    print("\n" + "=" * 70)
    print("BACKEND TEST 3: analyze_scan_results wrapper parity")
    print("=" * 70)

    results = _build_sample_results()

    direct = analyze_results(results)
    wrapped = analyze_scan_results(results)

    assert isinstance(wrapped, AnalysisResult), "Wrapper must return AnalysisResult"
    assert wrapped.score == direct.score, "Wrapper should not change computed score"
    assert (
        wrapped.summary_counts == direct.summary_counts
    ), "Wrapper should preserve summary counts"
    assert [f.message for f in wrapped.findings] == [
        f.message for f in direct.findings
    ], "Wrapper should preserve findings ordering and messages"

    print("✅ PASS: analyze_scan_results behaves identically to analyze_results")
    return True

def main() -> int:
    tests = [
        ("test_analyze_results_empty", test_analyze_results_empty),
        ("test_analyze_results_sample_data", test_analyze_results_sample_data),
        ("test_analyze_scan_results_wrapper", test_analyze_scan_results_wrapper),
    ]

    all_ok = True
    for name, func in tests:
        try:
            ok = func()
        except AssertionError as e:
            all_ok = False
            print(f"❌ {name} FAILED: {e}")
        except Exception as e:
            all_ok = False
            print(f"❌ {name} ERROR: {e}")
        else:
            if not ok:
                all_ok = False
                print(f"❌ {name} returned False")

    print("\n" + "=" * 70)
    if all_ok:
        print("✅ ALL BACKEND TESTS PASSED")
        return 0
    else:
        print("❌ SOME BACKEND TESTS FAILED")
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
