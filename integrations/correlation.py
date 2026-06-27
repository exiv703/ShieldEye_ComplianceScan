"""ML-based and heuristic correlation of SurfaceScan findings to compliance controls."""

from __future__ import annotations

import logging
import math
from typing import Any, Literal

logger = logging.getLogger("shieldeye.integrations.correlation")

# 0.75 was chosen after a few runs as a reasonable default for compliance mapping.
# Override via config if your data looks different.
DEFAULT_CONFIDENCE_THRESHOLD = 0.75

try:
    from sentence_transformers import SentenceTransformer  # type: ignore[import-not-found]

    _SENTENCE_TRANSFORMERS_AVAILABLE = True
except ImportError:
    _SENTENCE_TRANSFORMERS_AVAILABLE = False


class HeuristicBackend:
    """Rule-based matcher used when ML is disabled or unavailable."""

    def correlate(self, finding_category: str, control_id: str) -> float:
        confidence, _ = self.correlate_with_reason(finding_category, control_id)
        return confidence

    def correlate_with_reason(
        self, finding_category: str, control_id: str
    ) -> tuple[float, str]:
        # match on category, not just an id prefix - prefix matching was too
        # greedy and pulled in unrelated controls
        if finding_category == "ssl":
            if control_id == "CIS-4.1.3":
                return (
                    1.0,
                    "category=ssl matches CIS-4.1.3 (auditd telemetry integrity control)",
                )
            if control_id == "CIS-4.2.1":
                return (
                    1.0,
                    "category=ssl matches CIS-4.2.1 (logging configuration hardening control)",
                )
            if control_id.startswith("CIS-4."):
                return (
                    0.7,
                    "category=ssl matches CIS-4.x (secure configuration controls)",
                )

        if finding_category == "privacy":
            if control_id == "GDPR-32.1.1":
                return (
                    1.0,
                    "category=privacy matches GDPR-32.1.1 (encryption in transit)",
                )
            if control_id == "GDPR-32.2.1":
                return (
                    1.0,
                    "category=privacy matches GDPR-32.2.1 (consent/security header expectations)",
                )
            if control_id.startswith("GDPR-"):
                return (
                    0.7,
                    "category=privacy matches GDPR-* (data protection and accountability controls)",
                )

        if finding_category == "headers" and control_id.startswith("CIS-5."):
            return (
                1.0,
                "category=headers matches CIS-5.x (access/session hardening controls)",
            )
        if finding_category == "cookies" and control_id.startswith("CIS-5."):
            return (
                1.0,
                "category=cookies matches CIS-5.x (session/cookie hardening controls)",
            )
        if finding_category == "cookies" and control_id.startswith("GDPR-"):
            return (
                1.0,
                "category=cookies matches GDPR-* (consent and privacy handling controls)",
            )
        if finding_category == "tracking" and control_id.startswith("GDPR-"):
            return (
                1.0,
                "category=tracking matches GDPR-* (tracking transparency and consent obligations)",
            )

        return (
            0.0,
            f"no heuristic rule matched category={finding_category} and control_id={control_id}",
        )


class MLBackend:
    """Embedding matcher with safe fallback to heuristic behavior on errors."""

    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        self._available = _SENTENCE_TRANSFORMERS_AVAILABLE
        self._model_name = model_name
        self._model: Any | None = None

    def _load_model(self) -> Any | None:
        if self._model is not None:
            return self._model
        if not self._available:
            return None
        try:
            from sentence_transformers import SentenceTransformer

            self._model = SentenceTransformer(self._model_name)
            return self._model
        except Exception as exc:
            logger.warning("Failed to load model %s: %s", self._model_name, exc)
            self._available = False
            return None

    @staticmethod
    def _cosine_similarity(a: Any, b: Any) -> float:
        if hasattr(a, "tolist"):
            a = a.tolist()
        if hasattr(b, "tolist"):
            b = b.tolist()
        dot = sum(x * y for x, y in zip(a, b))
        norm_a = math.sqrt(sum(x * x for x in a))
        norm_b = math.sqrt(sum(x * x for x in b))
        if norm_a == 0.0 or norm_b == 0.0:
            return 0.0
        return float(dot / (norm_a * norm_b))

    def correlate(self, finding_description: str, control_description: str) -> float:
        model = self._load_model()
        if model is None:
            logger.warning(
                "MLBackend unavailable: sentence-transformers not installed or model failed to load"
            )
            return 0.0
        try:
            embeddings = model.encode([finding_description, control_description])
            similarity = self._cosine_similarity(embeddings[0], embeddings[1])
            return float(similarity)
        except Exception as exc:
            logger.warning("ML correlation failed: %s", exc)
            return 0.0


class CorrelationEngine:
    """Coordinates ML scoring and heuristic fallback with explainable reasons."""

    def __init__(
        self,
        backend: Literal["heuristic", "ml"] = "heuristic",
        confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD,
    ):
        self._backend_type = backend
        self._confidence_threshold = confidence_threshold
        self._heuristic = HeuristicBackend()
        self._ml: MLBackend | None = None
        if backend == "ml":
            self._ml = MLBackend()

    def correlate(
        self,
        finding_description: str,
        control_description: str,
        finding_category: str,
        control_id: str,
    ) -> dict[str, Any]:
        # log the actual backend that decided (ml vs heuristic) so the reason
        # we record later isn't mislabeled
        if self._backend_type == "ml" and self._ml is not None and self._ml._available:
            ml_confidence = self._ml.correlate(finding_description, control_description)
            if ml_confidence >= self._confidence_threshold:
                logger.info(
                    "ML correlation: %s (confidence=%.2f, method=%s)",
                    control_id,
                    ml_confidence,
                    "ml",
                    extra={"method": "ml", "confidence": ml_confidence},
                )
                return {
                    "matched": True,
                    "confidence": ml_confidence,
                    "method": "ml",
                    "reason": f"ML semantic similarity >= {self._confidence_threshold}",
                }
            logger.info(
                "ML confidence %.2f below threshold; falling back to heuristic",
                ml_confidence,
            )
            heuristic_confidence, heuristic_reason = (
                self._heuristic.correlate_with_reason(finding_category, control_id)
            )
            # keep the reason explicit so the control mapping can be traced back
            if heuristic_confidence > 0:
                reason = (
                    f"ML confidence {ml_confidence:.2f} < threshold {self._confidence_threshold:.2f}; "
                    f"heuristic matched via category-prefix rule ({heuristic_reason})"
                )
            else:
                reason = (
                    f"ML confidence {ml_confidence:.2f} < threshold {self._confidence_threshold:.2f}; "
                    f"heuristic did not match ({heuristic_reason})"
                )
            logger.info(
                "Heuristic correlation: %s (method=heuristic, reason=%s)",
                control_id,
                reason,
                extra={
                    "method": "heuristic",
                    "confidence": heuristic_confidence,
                    "reason": reason,
                },
            )
            return {
                "matched": heuristic_confidence > 0,
                "confidence": heuristic_confidence,
                "method": "heuristic",
                "reason": reason,
            }

        heuristic_confidence, heuristic_reason = self._heuristic.correlate_with_reason(
            finding_category, control_id
        )
        logger.info(
            "Heuristic correlation: %s (method=heuristic, reason=%s)",
            control_id,
            heuristic_reason,
            extra={
                "method": "heuristic",
                "confidence": heuristic_confidence,
                "reason": heuristic_reason,
            },
        )
        return {
            "matched": heuristic_confidence > 0,
            "confidence": heuristic_confidence,
            "method": "heuristic",
            "reason": heuristic_reason,
        }


def get_correlation_engine() -> CorrelationEngine:
    from backend.utils.config import get_config

    config = get_config()
    enable_ml = getattr(config, "enable_ml_correlation", False)
    threshold = getattr(
        config, "ml_correlation_confidence_threshold", DEFAULT_CONFIDENCE_THRESHOLD
    )
    backend: Literal["heuristic", "ml"] = "ml" if enable_ml else "heuristic"
    return CorrelationEngine(backend=backend, confidence_threshold=threshold)

