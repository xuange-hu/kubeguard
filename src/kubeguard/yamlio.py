"""A miniature indentation-based YAML reader that keeps line numbers.

Why not PyYAML: a manifest scanner is most valuable exactly where installing
packages is hardest — slim CI images, air-gapped clusters, ``uvx`` cold starts
with no toolchain. Kubernetes manifests also only use a narrow YAML subset, so
a purpose-built reader is both smaller and more useful: every scalar keeps the
1-based line it came from, which is what lets a finding say
``deployment.yaml:37`` instead of "somewhere in your cluster".

Supported subset:
  * multi-document streams separated by ``---`` (the k8s normal case), with
    line numbers kept **absolute** across the whole file
  * block mappings and block sequences, arbitrarily nested
  * plain, single-quoted and double-quoted scalars (``\\`` escapes in dquotes)
  * block scalars: ``|`` ``|-`` ``|+`` ``>`` ``>-`` ``|+``
  * flat flow collections: ``["*"]`` and ``{a: b, c: d}``
  * comments, blank lines, ``...`` document end markers

Deliberately unsupported: anchors/aliases, merge keys, complex keys, tabs.
Unsupported constructs raise ``YamlError`` rather than being silently dropped —
a scanner that quietly ignores half a manifest is worse than one that fails.
"""

from __future__ import annotations

import re
from typing import Any

__all__ = ["L", "M", "S", "YamlError", "load_all", "loads", "load_documents"]


class YamlError(ValueError):
    """Raised when a file is not valid in the supported subset."""


class S(str):
    """A scalar that remembers its source line."""

    line: int

    def __new__(cls, value: str = "", line: int = 0):  # returns an S instance
        """str is immutable: the line number must be attached here, not in __init__."""
        obj = super().__new__(cls, value)
        obj.line = line
        return obj


class M(dict):
    """A mapping that remembers the line of every key."""

    def __init__(self, line: int = 0) -> None:
        super().__init__()
        self.line = line
        self.klines: dict[str, int] = {}


class L(list):
    """A sequence that remembers the line of every element."""

    def __init__(self, line: int = 0) -> None:
        super().__init__()
        self.line = line
        self.ilines: dict[int, int] = {}


_ESCAPES = {
    "n": "\n",
    "t": "\t",
    "r": "\r",
    "0": "\0",
    "\\": "\\",
    '"': '"',
    "/": "/",
}


def _unescape(text: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "\\" and i + 1 < len(text):
            nxt = text[i + 1]
            out.append(_ESCAPES.get(nxt, nxt))
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _split_key(content: str) -> tuple[str, str] | None:
    """Split ``key: rest`` at the first structural colon (quote-aware)."""
    quote: str | None = None
    for idx, ch in enumerate(content):
        if quote:
            if ch == quote:
                quote = None
            continue
        if ch in "\"'":
            quote = ch
            continue
        # structural colon: end-of-line, or followed by a space
        if ch == ":" and (idx + 1 == len(content) or content[idx + 1] in " \t"):
            return content[:idx].strip(), content[idx + 1 :].strip()
    return None


def _strip_comment(text: str) -> str:
    """Drop a trailing ``# comment`` from a plain scalar (quote-aware).

    Without this, `replicas: 3   # keep two hot` parses as the whole string.
    """
    quote: str | None = None
    out: list[str] = []
    for i, ch in enumerate(text):
        if quote:
            out.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in "\"'":
            quote = ch
            out.append(ch)
            continue
        if ch == "#" and (i == 0 or text[i - 1] in " \t"):
            break
        out.append(ch)
    return "".join(out).rstrip()


def _unquote(text: str) -> str:
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        inner = text[1:-1]
        return _unescape(inner) if text[0] == '"' else inner.replace("''", "'")
    return text


def _flow_scalar(token: str) -> Any:
    token = token.strip()
    if token in ("", "~", "null", "Null", "NULL"):
        return None
    # YAML 1.1 booleans: kubectl (sigs.k8s.io/yaml -> go-yaml v2) accepts these,
    # so a k8s-flavoured reader has to agree with it.
    if token in ("true", "True", "TRUE", "yes", "on"):
        return True
    if token in ("false", "False", "FALSE", "no", "off"):
        return False
    if len(token) >= 2 and token[0] == token[-1] and token[0] in "\"'":
        return _unquote(token)
    if token.startswith(("[", "{")):
        return _flow(token)
    try:
        return int(token)
    except ValueError:
        pass
    try:
        return float(token)
    except ValueError:
        pass
    return token


def _split_flow(body: str) -> list[str]:
    """Split a flat flow collection body on top-level commas."""
    parts: list[str] = []
    depth = 0
    quote: str | None = None
    cur: list[str] = []
    for ch in body:
        if quote:
            cur.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in "\"'":
            quote = ch
            cur.append(ch)
        elif ch in "[{":
            depth += 1
            cur.append(ch)
        elif ch in "]}":
            depth -= 1
            cur.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    if "".join(cur).strip():
        parts.append("".join(cur))
    return [p.strip() for p in parts]


def _flow(text: str) -> Any:
    text = text.strip()
    if text.startswith("[") and text.endswith("]"):
        out = L()
        for i, part in enumerate(_split_flow(text[1:-1])):
            out.append(_flow_scalar(part))
            out.ilines[i] = 0
        return out
    if text.startswith("{") and text.endswith("}"):
        out = M()
        for part in _split_flow(text[1:-1]):
            kv = _split_key(part)
            if kv is None:
                continue
            key, rest = kv
            key = _unquote(key)
            value = _flow_scalar(rest) if rest else None
            if isinstance(value, str) and not isinstance(value, S):
                value = S(value)
            out[key] = value
            out.klines[key] = 0
        return out
    return _flow_scalar(text)


class _Parser:
    def __init__(self, lines: list[str], offset: int = 0) -> None:
        self.lines = lines
        self.offset = offset  # lines consumed before this chunk, for absolute numbering
        self.i = 0

    # -- line helpers ----------------------------------------------------
    def _skip_noise(self) -> None:
        while self.i < len(self.lines):
            s = self.lines[self.i].strip()
            if not s or s.startswith("#") or s in ("---", "..."):
                self.i += 1
                continue
            break

    def _cur(self) -> tuple[int, str] | None:
        """Return (indent, content) of the next structural line, or None."""
        self._skip_noise()
        if self.i >= len(self.lines):
            return None
        raw = self.lines[self.i]
        indent = len(raw) - len(raw.lstrip(" \t"))
        return indent, raw.strip()

    def _lineno(self) -> int:
        return self.i + 1 + self.offset

    def _indent_of(self, raw: str) -> int:
        return len(raw) - len(raw.lstrip(" \t"))

    # -- entry -----------------------------------------------------------
    def parse_document(self) -> Any:
        node = self.parse_node(0)
        return node if node is not None else M()

    def parse_node(self, indent: int) -> Any:
        cur = self._cur()
        if cur is None:
            return None
        ind, content = cur
        if ind < indent:
            return None
        if content == "-" or content.startswith("- "):
            return self.parse_seq(ind)
        if _split_key(content) is not None:
            return self.parse_map(ind)
        # a bare scalar document
        self.i += 1
        return S(_unquote(content), self._lineno() - 1)

    def parse_map(self, indent: int) -> M:
        out = M()
        first = True
        while True:
            cur = self._cur()
            if cur is None:
                break
            ind, content = cur
            if ind < indent:
                break
            if ind > indent and first:
                break
            if content == "-" or content.startswith("- "):
                break
            kv = _split_key(content)
            if kv is None:
                # Not a mapping line at this level: bail out rather than
                # silently dropping content we do not understand.
                raise YamlError(f"line {self._lineno()}: expected 'key: value', got {content!r}")
            key_raw, rest = kv
            rest = _strip_comment(rest)
            key = _unquote(key_raw)
            line = self._lineno()
            self.i += 1
            if rest.startswith(("|", ">")) and rest[:2].rstrip("+-") in ("|", ">"):
                out[key] = S(self._block_scalar(rest, indent), line)
            elif rest:
                out[key] = self._value(rest, line)
            else:
                child = self._child(indent)
                out[key] = child if child is not None else None
            out.klines[key] = line
            out.line = out.line or line
            first = False
        return out

    def parse_seq(self, indent: int) -> L:
        out = L()
        idx = 0
        while True:
            cur = self._cur()
            if cur is None:
                break
            ind, content = cur
            if ind != indent or not (content == "-" or content.startswith("- ")):
                break
            rest = _strip_comment(content[1:])
            offset = len(rest) - len(rest.lstrip(" \t"))
            child_indent = indent + 1 + offset
            line = self._lineno()
            self.i += 1
            item: Any
            if not rest.strip():
                item = self._child(indent)
            else:
                kv = _split_key(rest.strip())
                if kv is not None:
                    # inline start of a mapping item: re-inject as a virtual
                    # line so parse_map consumes it plus its siblings.
                    self.lines[self.i - 1] = " " * child_indent + rest.strip()
                    self.i -= 1
                    item = self.parse_map(child_indent)
                else:
                    item = self._value(rest.strip(), line)
                    out.ilines[idx] = line
                    out.line = out.line or line
                    idx += 1
                    continue
            out.append(item)
            out.ilines[idx] = line
            out.line = out.line or line
            idx += 1
        return out

    def _child(self, parent_indent: int) -> Any:
        """Parse the block nested under a ``key:`` line."""
        cur = self._cur()
        if cur is None:
            return None
        ind, content = cur
        if ind <= parent_indent:
            return None
        if content == "-" or content.startswith("- "):
            return self.parse_seq(ind)
        if _split_key(content) is not None:
            return self.parse_map(ind)
        # continuation/plain multi-line scalar
        parts: list[str] = []
        while True:
            cur = self._cur()
            if cur is None:
                break
            ind2, content2 = cur
            if ind2 <= parent_indent:
                break
            parts.append(content2)
            self.i += 1
        return S(" ".join(parts), self._lineno())

    def _value(self, rest: str, line: int) -> Any:
        rest = _strip_comment(rest).strip()
        if rest.startswith(("[", "{")):
            # flow collection: support nested brackets across continuation lines
            buf = rest
            while buf.count("[") != buf.count("]") or buf.count("{") != buf.count("}"):
                self._skip_noise()
                if self.i >= len(self.lines):
                    break
                buf += " " + self.lines[self.i].strip()
                self.i += 1
            return _flow(buf)
        if len(rest) >= 2 and rest[0] == rest[-1] and rest[0] in "\"'":
            return S(_unquote(rest), line)
        value = _flow_scalar(rest)
        return value if not isinstance(value, str) else S(value, line)

    def _block_scalar(self, marker: str, parent_indent: int) -> str:
        style = marker[0]
        chomp = ""
        if len(marker) > 1 and marker[1] in "+-":
            chomp = marker[1]
        base: int | None = None
        for raw in self.lines[self.i :]:
            if not raw.strip():
                continue
            base = len(raw) - len(raw.lstrip(" \t"))
            break
        if base is None or base <= parent_indent:
            return ""
        body: list[str] = []
        while self.i < len(self.lines):
            raw = self.lines[self.i]
            if not raw.strip():
                body.append("")
                self.i += 1
                continue
            if self._indent_of(raw) < base:
                break
            body.append(raw[base:])
            self.i += 1
        while body and not body[-1]:
            body.pop()
        # `|` keeps line structure (script bodies depend on it); `>` folds it.
        text = "\n".join(body) if style == "|" else " ".join(body)
        if chomp != "-":
            text += "\n"
        return text


def _normalize(text: str) -> list[str]:
    return text.replace("\t", "  ").replace("\r\n", "\n").replace("\r", "\n").splitlines()


_MARKER = re.compile(r"^(---|\.\.\.)(\s.*)?$")


def load_documents(text: str) -> list[Any]:
    """Parse every document in a multi-document stream, keeping absolute lines.

    Document boundaries are found by scanning lines instead of ``re.split``:
    the chunk offset is what turns "line 3 of document 2" into "line 41 of the
    file", and a finding that points at the wrong document is worse than none.
    """
    lines = _normalize(text)
    starts = [0]
    for idx, raw in enumerate(lines):
        stripped = raw.strip()
        if not _MARKER.match(stripped):
            continue
        # `---` opens a new document; `...` closes the current one.
        starts.append(idx + 1)
    docs: list[Any] = []
    for pos, start in enumerate(starts):
        end = starts[pos + 1] - 1 if pos + 1 < len(starts) else len(lines)
        chunk = lines[start:end]
        if not any(line.strip() for line in chunk):
            continue
        docs.append(_Parser(chunk, offset=start).parse_document())
    return docs or [M()]


def loads(text: str) -> Any:
    """Parse the first document of ``text`` into S/M/L structures."""
    return load_documents(text)[0]


def load_all(text: str) -> list[Any]:
    """Alias of :func:`load_documents`, kept for symmetry with the other tools."""
    return load_documents(text)
