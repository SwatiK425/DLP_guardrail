"""
Tests for the provider-agnostic BYOK LLM judge.

Covers:
  - PROVIDER_BASE_URLS / defaults / env-key map completeness
  - mask_key never reveals the full key
  - judge init validates the provider
  - response parsing for each provider shape (OpenAI-compat, google, anthropic)
  - engine resolves the key from the provider's env var (BYOK contract)
  - legacy gemini_api_key alias still works
"""
import unittest
import os
from unittest import mock

from dlp_guardrail_with_llm import (
    PROVIDER_BASE_URLS,
    PROVIDER_DEFAULT_MODELS,
    PROVIDER_ENV_KEYS,
    mask_key,
    ProviderLLMJudge,
    IntentGuardrailWithLLM,
)


class ProviderTableTest(unittest.TestCase):
    def test_all_five_providers_with_urls_defaults_env(self):
        expected = {"google", "anthropic", "openai", "openrouter", "opencode-zen"}
        self.assertEqual(set(PROVIDER_BASE_URLS), expected)
        self.assertEqual(set(PROVIDER_DEFAULT_MODELS), expected)
        self.assertEqual(set(PROVIDER_ENV_KEYS), expected)

    def test_google_model_is_current_not_deprecated(self):
        # Regression: this was gemini-2.0-flash-exp (deprecated -> judge always fell back).
        self.assertNotEqual(PROVIDER_DEFAULT_MODELS["google"], "gemini-2.0-flash-exp")
        self.assertIn("2.5", PROVIDER_DEFAULT_MODELS["google"])


class MaskKeyTest(unittest.TestCase):
    def test_never_masks_but_hides_key(self):
        full = "sk-abcdefghijklmnopqrstuvwxyz123456"
        masked = mask_key(full)
        self.assertNotIn(full, masked)
        self.assertLess(len(masked), 12)
        self.assertNotEqual(masked, "*" * len(full))

    def test_empty_key(self):
        self.assertEqual(mask_key(""), "<unset>")

    def test_short_key(self):
        self.assertEqual(mask_key("short"), "*****")


class ProviderJudgeTest(unittest.TestCase):
    def test_unknown_provider_raises(self):
        with self.assertRaises(ValueError):
            ProviderLLMJudge("not-a-provider", "key")

    def test_default_model_applied(self):
        j = ProviderLLMJudge("openai", "sk-test")
        self.assertEqual(j.model, PROVIDER_DEFAULT_MODELS["openai"])

    def test_explicit_model_override(self):
        j = ProviderLLMJudge("openrouter", "key", model="anthropic/claude-3.5")
        self.assertEqual(j.model, "anthropic/claude-3.5")

    def _judge_with_text(self, provider, response_text, key="secret-key"):
        j = ProviderLLMJudge(provider, key)
        j._call_provider = lambda _p: response_text
        return j

    def test_parses_openai_compat_json(self):
        j = self._judge_with_text(
            "openai",
            '{"risk_score": 95, "verdict": "BLOCKED", "reasoning": "exfil", "detected_threats": ["training_data"]}',
        )
        r = j.analyze("some prompt")
        self.assertEqual(r["risk_score"], 95)
        self.assertEqual(r["verdict"], "BLOCKED")
        self.assertEqual(r["detected_threats"], ["training_data"])

    def test_parses_nested_braces_json(self):
        # Old regex r'\{[^}]+\}' choked on nested braces; example-only JSON is fine
        # because first-{-to-last-} extraction is used.
        text = ('Sure. {"risk_score": 40, "verdict": "MEDIUM_RISK", '
                '"reasoning": "a { b } c", "detected_threats": []}')
        r = self._judge_with_text("google", text).analyze("p")
        self.assertEqual(r["risk_score"], 40)
        self.assertEqual(r["verdict"], "MEDIUM_RISK")

    def test_manual_fallback_when_no_json(self):
        j = self._judge_with_text("anthropic", "risk_score: 70 and disclose")
        r = j.analyze("p")
        self.assertEqual(r["risk_score"], 70)
        self.assertEqual(r["verdict"], "HIGH_RISK")

    def test_status_reports_provider_and_model(self):
        j = ProviderLLMJudge("opencode-zen", "key")
        st = j.get_status()
        self.assertEqual(st["provider"], "opencode-zen")
        self.assertEqual(st["model"], PROVIDER_DEFAULT_MODELS["opencode-zen"])
        self.assertTrue(st["available"])


class EngineBYOKResolutionTest(unittest.TestCase):
    def test_engine_reads_provider_env_key(self):
        with mock.patch.dict(os.environ, {"OPENAI_API_KEY": "sk-from-env"}, clear=False):
            with mock.patch(
                "dlp_guardrail_with_llm.ProviderLLMJudge"
            ) as mock_cls:
                IntentGuardrailWithLLM(provider="openai")
                mock_cls.assert_called_once()
                args, kwargs = mock_cls.call_args
                self.assertEqual(args[1], "sk-from-env")  # api_key resolved from env

    def test_legacy_gemini_api_key_alias(self):
        with mock.patch("dlp_guardrail_with_llm.ProviderLLMJudge") as mock_cls:
            IntentGuardrailWithLLM(gemini_api_key="legacy-key")
            args, _ = mock_cls.call_args
            self.assertEqual(args[0], "google")
            self.assertEqual(args[1], "legacy-key")

    def test_no_key_no_judge(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            with mock.patch("dlp_guardrail_with_llm.ProviderLLMJudge") as mock_cls:
                g = IntentGuardrailWithLLM(provider="google")
                mock_cls.assert_not_called()
                self.assertIsNone(g.llm_judge)


if __name__ == "__main__":
    unittest.main(verbosity=2)