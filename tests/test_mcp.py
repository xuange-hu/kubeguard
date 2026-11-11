"""MCP surface: the served names must match the manifest, with descriptions."""

from __future__ import annotations

import asyncio

import pytest

from kubeguard import mcp_server

pytest.importorskip("mcp")


def test_served_tools_match_manifest_with_descriptions():
    """The names an agent calls must be the names the manifest promises, and
    FastMCP serves an empty description when the registered function has no
    docstring - an unidentified tool is an uncallable tool."""
    server = mcp_server.build_server()
    tools = asyncio.run(server.list_tools())
    served = {t.name for t in tools}
    manifest = {t["name"] for t in mcp_server.tool_manifest()}
    assert served == manifest, f"only served: {served - manifest}; only manifest: {manifest - served}"
    for t in tools:
        assert (t.description or "").strip(), f"{t.name} has no description"


def test_manifest_lists_every_declared_tool():
    assert {t["name"] for t in mcp_server.tool_manifest()} == {
        str(entry["name"]) if isinstance(entry, dict) else str(entry)
        for entry in mcp_server.TOOLS
    }
