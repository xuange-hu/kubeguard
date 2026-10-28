"""Tests for the line-keeping YAML reader.

The property that matters is not "it parses YAML" — it is "the line number it
reports points at the line a human would go edit". Everything here pins that.
"""

from __future__ import annotations

import pytest

from kubeguard.yamlio import L, M, S, YamlError, load_documents, loads


def test_scalar_keeps_line():
    doc = loads("apiVersion: v1\nkind: Pod\n")
    assert doc["apiVersion"] == "v1"
    assert doc.klines["kind"] == 2


def test_nested_map_lines():
    doc = loads("spec:\n  template:\n    spec:\n      hostPID: true\n")
    spec = doc["spec"]["template"]["spec"]
    assert spec.klines["hostPID"] == 4


def test_sequence_item_lines():
    doc = loads("containers:\n  - name: a\n  - name: b\n  - name: c\n")
    seq = doc["containers"]
    assert isinstance(seq, L)
    assert [seq.ilines[i] for i in range(3)] == [2, 3, 4]


def test_sequence_of_maps_inline():
    doc = loads("rules:\n  - apiGroups: [\"\"]\n    resources: [\"pods\"]\n    verbs: [\"get\"]\n")
    rule = doc["rules"][0]
    assert rule["resources"] == ["pods"]
    assert rule.klines["verbs"] == 4


def test_flow_sequence():
    doc = loads("verbs: [\"*\", \"get\"]\n")
    assert doc["verbs"] == ["*", "get"]


def test_flow_map():
    doc = loads("labels: {app: web, tier: front}\n")
    assert doc["labels"]["app"] == "web"


def test_quoted_scalar_with_colon():
    doc = loads("command: \"sh -c 'echo a: b'\"\n")
    assert doc["command"] == "sh -c 'echo a: b'"


def test_comment_stripped_from_scalar():
    doc = loads("replicas: 3   # keep two hot\n")
    assert doc["replicas"] == 3  # numeric scalars keep their type


def test_comment_inside_quotes_is_kept():
    doc = loads("value: \"a # b\"\n")
    assert doc["value"] == "a # b"


def test_block_scalar_literal():
    text = "script: |\n  echo one\n  echo two\nother: 1\n"
    doc = loads(text)
    assert doc["script"] == "echo one\necho two\n"
    assert doc["other"] == 1


def test_block_scalar_folded():
    doc = loads("note: >\n  one\n  two\n")
    assert doc["note"] == "one two\n"


def test_yaml11_booleans_match_kubectl():
    doc = loads("a: yes\nb: no\nc: on\nd: off\n")
    assert (doc["a"], doc["b"], doc["c"], doc["d"]) == (True, False, True, False)


def test_integers_and_floats():
    doc = loads("port: 8080\nratio: 0.5\n")
    assert doc["port"] == 8080
    assert doc["ratio"] == 0.5


def test_null_forms():
    doc = loads("a: ~\nb: null\nc:\n")
    assert doc["a"] is None and doc["b"] is None and doc["c"] is None


def test_multidoc_keeps_absolute_lines():
    text = "kind: A\nspec:\n  x: 1\n---\nkind: B\nspec:\n  y: 2\n"
    docs = load_documents(text)
    assert len(docs) == 2
    assert docs[0]["kind"] == "A"
    assert docs[1]["kind"] == "B"
    assert docs[1].klines["kind"] == 5          # absolute, not 1
    assert docs[1]["spec"].klines["y"] == 7


def test_multidoc_with_leading_marker():
    docs = load_documents("---\nkind: A\n---\nkind: B\n")
    assert len(docs) == 2
    assert docs[1].klines["kind"] == 4


def test_document_end_marker():
    docs = load_documents("kind: A\n...\nkind: B\n")
    assert len(docs) == 2
    assert docs[1]["kind"] == "B"


def test_empty_text_is_empty_map():
    assert loads("") == {}


def test_blank_and_comment_lines_are_noise():
    doc = loads("# top\n\nkind: Pod\n\n# trailing\n")
    assert doc.klines["kind"] == 3


def test_unparseable_line_raises():
    with pytest.raises(YamlError):
        loads("spec:\n  - name: a\nnot a mapping at all here\n")


def test_types_are_the_documented_shapes():
    doc = loads("a: 1\nb:\n  - x\n")
    assert isinstance(doc, M)
    assert isinstance(doc["b"], L)
    assert isinstance(S("x", 3), str)


def test_flow_collection_spans_continuation_lines():
    text = "rules:\n  - verbs: [\"get\",\n      \"list\"]\n"
    doc = loads(text)
    assert doc["rules"][0]["verbs"] == ["get", "list"]


def test_tabs_are_normalised():
    doc = loads("spec:\n\tx: 1\n")
    assert doc["spec"]["x"] == 1
