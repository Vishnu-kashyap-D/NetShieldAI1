"""Both chatbots' Gemini calls: bounded by a timeout, and a failed/slow call degrades to an honest message."""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from google import genai

from app.config import settings  # first: it puts the repo root (cyber_ai) on sys.path
from app import chat_service


class _FakeClient:
    """Stands in for google.genai.Client; records how it was built and fails or answers on demand."""

    instances: list["_FakeClient"] = []
    behaviour: object = "ok"  # "ok", or an exception instance to raise

    def __init__(self, api_key=None, http_options=None):
        self.api_key = api_key
        self.http_options = http_options
        _FakeClient.instances.append(self)
        self.models = SimpleNamespace(generate_content=self._generate)

    def _generate(self, model, contents, config):
        self.model = model
        if isinstance(_FakeClient.behaviour, Exception):
            raise _FakeClient.behaviour
        return SimpleNamespace(text="A grounded answer.")


# The smallest alert context answer_with_llm() reads (the real one comes from routers/chat.py).
ALERT_CONTEXT = {"classifier_shap": [], "anomaly_shap": [], "relevant_feature_values": {}, "feature_glossary": {}}


@pytest.fixture()
def fake_gemini(monkeypatch):
    _FakeClient.instances = []
    _FakeClient.behaviour = "ok"
    monkeypatch.setattr(genai, "Client", _FakeClient)
    monkeypatch.setattr(settings, "gemini_api_key", "test-key")
    monkeypatch.setattr(settings, "gemini_model", "gemini-test-flash")
    monkeypatch.setattr(settings, "gemini_timeout_seconds", 12.5)
    return _FakeClient


def test_both_chatbots_use_the_configured_model_and_a_timeout(fake_gemini):
    chat_service.answer_project_question("What does the Autoencoder do?")
    chat_service.answer_with_llm("Why?", ALERT_CONTEXT)

    assert len(fake_gemini.instances) == 2
    for client in fake_gemini.instances:
        assert client.api_key == "test-key"
        assert client.model == "gemini-test-flash"
        assert client.http_options.timeout == 12_500  # the SDK takes milliseconds


def test_a_timed_out_project_question_gets_an_answer_not_an_exception(fake_gemini):
    fake_gemini.behaviour = TimeoutError("read timed out")
    answer = chat_service.answer_project_question("What does the Autoencoder do?")
    assert "couldn't answer" in answer.text


def test_a_timed_out_alert_question_raises_the_handled_unavailable_error(fake_gemini):
    """The per-alert route turns LlmUnavailableError into its "AI explanation service is unavailable" reply."""
    fake_gemini.behaviour = TimeoutError("read timed out")
    with pytest.raises(chat_service.LlmUnavailableError):
        chat_service.answer_with_llm("Why?", ALERT_CONTEXT)
