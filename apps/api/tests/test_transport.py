"""Robustesse du transport IA face aux réponses réelles d'OpenRouter (vides, tronquées)."""
import json

import httpx
import pytest

from secuscan.ai import enricher as enricher_mod
from secuscan.ai.enricher import MAX_OUTPUT_TOKENS_RETRY, AIUnavailable, Enricher
from secuscan.config import Settings
from secuscan.storage import Storage


def _response(content, finish_reason="stop"):
    return {
        "choices": [{"message": {"content": content}, "finish_reason": finish_reason}],
        "usage": {"prompt_tokens": 100, "completion_tokens": 50},
    }


@pytest.fixture
def make_enricher(tmp_path, monkeypatch):
    monkeypatch.setattr(enricher_mod.time, "sleep", lambda _s: None)

    def build(responses: list[dict], seen: list[dict]):
        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(json.loads(request.content))
            return httpx.Response(200, json=responses.pop(0))

        real_client = httpx.Client
        monkeypatch.setattr(enricher_mod.httpx, "Client", lambda **kw: real_client(transport=httpx.MockTransport(handler)))
        settings = Settings(_env_file=None, openrouter_api_key="test-key-placeholder", secuscan_data_dir=tmp_path)
        return Enricher(settings, Storage(tmp_path / "t.db"))

    return build


def test_truncated_response_is_retried_with_larger_limit(make_enricher):
    seen: list[dict] = []
    e = make_enricher([_response('{"verdict": "unce', "length"), _response('{"verdict": "uncertain"}')], seen)
    assert e._complete("prompt de test")["verdict"] == "uncertain"
    assert seen[1]["max_tokens"] == MAX_OUTPUT_TOKENS_RETRY
    assert e.stats.tokens == 300  # les jetons de la réponse tronquée sont aussi comptés


def test_empty_content_is_retried_then_reported(make_enricher):
    seen: list[dict] = []
    e = make_enricher([_response(None), _response(None), _response(None)], seen)
    with pytest.raises(AIUnavailable, match="réponse vide"):
        e._complete("prompt de test")
    assert len(seen) == 3
