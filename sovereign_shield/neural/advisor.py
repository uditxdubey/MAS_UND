"""
sovereign_shield/neural/advisor.py

Sovereign Shield — Neural Policy Advisor
Local LLM enrichment layer for EU AI Act risk classification.

CURRENT STATE: Stub mode — logs placeholder tags without LLM inference.
This is intentional. The advisor is ADVISORY ONLY and never affects
the symbolic verdict (PASS/HALT). The Shield works fully without it.

TO ACTIVATE REAL LLM (Phase 2):
    1. pip install llama-cpp-python
    2. Download llama3-8b-instruct.Q4_K_M.gguf to ./models/
    3. Set enabled=True and stub_mode=False in NeuralAdvisorPolicy
    4. Uncomment the _run_inference method body below

Depends on: neural_policy.py, audit/logger.py
"""

import threading
from sovereign_shield.symbolic.neural_policy import NeuralAdvisorPolicy
from sovereign_shield.audit.logger           import audit_logger


# ── Risk tags the LLM classifies requests into ────────────────────────────────
RISK_TAGS = {
    "PII_LEAK"    : "Payload contains personal identifiable information",
    "MODEL_EXFIL" : "Possible AI model or weights exfiltration attempt",
    "DATA_EXFIL"  : "Possible bulk data exfiltration attempt",
    "BENIGN"      : "No risk detected",
    "UNKNOWN"     : "Could not classify — treat as elevated risk",
}


class NeuralAdvisor:
    """
    Async advisory layer — classifies outbound requests using a local LLM.

    Rules:
    - NEVER blocks the main thread
    - NEVER delays a PASS or HALT decision
    - NEVER overrides the symbolic verdict
    - Results are written to audit log only
    - Fails silently — Shield works without it
    """

    def __init__(self, policy: NeuralAdvisorPolicy):
        self.policy    = policy
        self._llm      = None
        self._ready    = False
        self._stub     = True   # Phase 1: stub mode always on

        if self.policy.enabled:
            threading.Thread(
                target=self._lazy_load,
                daemon=True,
                name="neural-advisor-loader",
            ).start()

    def _lazy_load(self) -> None:
        """
        Attempt to load the local LLM in background.
        Falls back to stub mode silently if unavailable.
        """
        try:
            from llama_cpp import Llama   # noqa: F401 — optional dependency
            self._llm   = Llama(
                model_path = self.policy.model_path,
                n_ctx      = 512,
                n_threads  = self.policy.n_threads,
                verbose    = False,
            )
            self._ready = True
            self._stub  = False
            audit_logger.log_shield_event(
                "neural_advisor_ready",
                f"model={self.policy.model_path}",
            )
        except ImportError:
            audit_logger.log_shield_event(
                "neural_advisor_stub",
                "llama-cpp-python not installed — stub mode active",
            )
        except Exception as e:
            audit_logger.log_shield_event(
                "neural_advisor_unavailable",
                f"model load failed: {e}",
            )

    def tag_async(self, url: str, payload_preview: str) -> None:
        """
        Fire-and-forget risk tagging.
        Called by interceptor after a PASS verdict.
        Never called after a HALT — no point tagging blocked requests.

        Args:
            url:             Destination URL
            payload_preview: First 200 chars of request payload
        """
        if not self.policy.enabled:
            return

        threading.Thread(
            target=self._classify,
            args=(url, payload_preview),
            daemon=True,
            name="neural-advisor-classify",
        ).start()

    def _classify(self, url: str, payload_preview: str) -> None:
        """
        Runs in background thread.
        Stub mode: logs UNKNOWN tag immediately.
        LLM mode:  runs inference and logs result.
        """
        if self._stub:
            self._log_tag(url, "UNKNOWN", source="stub")
            return

        try:
            prompt = (
                f"EU AI Act compliance check.\n"
                f"Outbound POST to: {url}\n"
                f"Payload preview: {payload_preview[:200]}\n"
                f"Classify risk in one word: "
                f"[PII_LEAK | MODEL_EXFIL | DATA_EXFIL | BENIGN | UNKNOWN]"
            )
            result = self._llm(
                prompt,
                max_tokens  = self.policy.max_tokens,
                temperature = self.policy.temperature,
            )
            raw_tag = result["choices"][0]["text"].strip().upper()
            tag     = raw_tag if raw_tag in RISK_TAGS else "UNKNOWN"
            self._log_tag(url, tag, source="llm")

        except Exception as e:
            self._log_tag(url, "UNKNOWN", source="error", detail=str(e))

    def _log_tag(
        self,
        url    : str,
        tag    : str,
        source : str = "stub",
        detail : str = "",
    ) -> None:
        """Write neural classification result to audit log."""
        audit_logger.log_pass(
            url         = url,
            guard       = "NeuralAdvisor",
            neural_tag  = tag,
            tag_meaning = RISK_TAGS.get(tag, ""),
            source      = source,
            detail      = detail,
        )