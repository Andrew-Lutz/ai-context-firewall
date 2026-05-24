"""
Unit tests for the RedactionEngine.
"""
import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.redaction.engine import RedactionEngine


@pytest.fixture
def engine():
    return RedactionEngine()


class TestMaskRedaction:
    def test_mask_ssn(self, engine):
        entities = [{"text": "123-45-6789", "label": "SSN", "start": 16, "end": 27, "type": "PHI"}]
        redacted, result = engine.redact("Patient SSN is 123-45-6789", entities, mode="mask")
        assert "123-45-6789" not in redacted
        assert "[" in redacted

    def test_mask_email(self, engine):
        entities = [{"text": "alice@corp.com", "label": "EMAIL", "start": 9, "end": 23, "type": "PII"}]
        redacted, result = engine.redact("Contact alice@corp.com now", entities, mode="mask")
        assert "alice@corp.com" not in redacted

    def test_empty_entities(self, engine):
        text = "Hello world"
        redacted, result = engine.redact(text, [], mode="mask")
        assert redacted == text


class TestHashRedaction:
    def test_hash_produces_consistent_output(self, engine):
        entities = [{"text": "secret123", "label": "SECRET", "start": 0, "end": 9, "type": "SECRET"}]
        r1, _ = engine.redact("secret123", entities, mode="hash")
        r2, _ = engine.redact("secret123", entities, mode="hash")
        assert r1 == r2

    def test_hash_removes_original(self, engine):
        entities = [{"text": "abc@test.com", "label": "EMAIL", "start": 0, "end": 12, "type": "PII"}]
        redacted, _ = engine.redact("abc@test.com", entities, mode="hash")
        assert "abc@test.com" not in redacted


class TestRedactionResult:
    def test_result_has_count(self, engine):
        entities = [
            {"text": "alice@corp.com", "label": "EMAIL", "start": 9, "end": 23, "type": "PII"},
            {"text": "123-45-6789", "label": "SSN", "start": 40, "end": 51, "type": "PHI"},
        ]
        _, result = engine.redact("Contact alice@corp.com. SSN is 123-45-6789.", entities)
        assert result is not None

    def test_no_mutation_on_empty(self, engine):
        text = "Safe text here"
        redacted, _ = engine.redact(text, [])
        assert redacted == text
