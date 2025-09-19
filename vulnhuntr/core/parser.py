"""
Solidity parser utilities.

We attempt to use tree-sitter with the Solidity grammar when available.
If not available, constructor raises RuntimeError so callers/tests can skip.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, List, Tuple


class SolidityParser:
    """Thin wrapper around tree-sitter Solidity grammar (if installed)."""

    def __init__(self) -> None:
        try:
            from tree_sitter import Parser  # type: ignore
            try:
                # Preferred: tree_sitter_languages provides many grammars including Solidity
                import tree_sitter_languages as tsl  # type: ignore
                self.language = tsl.get_language("solidity")
            except Exception as e:
                # Fallback: try solidity specific package if present (unlikely in this env)
                self.language = None
                raise RuntimeError("Solidity grammar not available: install tree-sitter-languages") from e
            self.parser = Parser()
            self.parser.set_language(self.language)
        except Exception as e:  # pragma: no cover - environment dependent
            # Signal to tests to skip
            raise RuntimeError("Solidity parser not properly configured") from e

    def parse_file(self, file_path: str | Path) -> Tuple[Any, str]:
        path = Path(file_path)
        content = path.read_text(encoding="utf-8")
        tree = self.parser.parse(content.encode("utf-8"))
        return tree, content

    # The following helpers are best-effort and rely on simple tree traversals.
    # Tests in this repo skip if parser isn't configured, so these serve as placeholders.

    def find_contracts(self, tree: Any) -> List[dict]:
        """Return a list of contracts with minimal metadata."""
        contracts: List[dict] = []
        # Simple traversal: look for nodes named 'contract_declaration'
        def walk(node):
            if node.type == "contract_declaration":
                # name is first identifier child
                name = None
                for child in node.children:
                    if child.type == "identifier":
                        name = child.text.decode("utf-8")
                        break
                contracts.append({"name": name or "", "type": "contract", "node": node})
            for c in getattr(node, "children", []):
                walk(c)
        walk(tree.root_node)
        return contracts

    def find_functions(self, tree: Any) -> List[dict]:
        """Return a list of functions with minimal metadata."""
        functions: List[dict] = []
        def walk(node):
            if node.type in ("function_definition", "constructor_definition"):
                # Attempt to extract a name
                name = "constructor" if node.type == "constructor_definition" else None
                for child in node.children:
                    if child.type == "identifier":
                        name = child.text.decode("utf-8")
                        break
                functions.append({"name": name or "", "node": node})
            for c in getattr(node, "children", []):
                walk(c)
        walk(tree.root_node)
        return functions

    def extract_function_calls(self, func_node: Any) -> List[dict]:
        """Extract member calls inside a given function node."""
        calls: List[dict] = []
        def walk(node):
            if node.type == "function_call_expression":
                # Search for member access pattern `object.member` then a call
                member = None
                for c in node.children:
                    if c.type == "member_access":
                        # e.g., address(this).balance or msg.sender.call
                        # try to extract the property name after '.'
                        parts = [ch for ch in c.children if hasattr(ch, "text")]
                        if parts:
                            member = parts[-1].text.decode("utf-8")
                calls.append({"type": "member", "method": member or "", "node": node})
            for c in getattr(node, "children", []):
                walk(c)
        walk(func_node)
        return calls

    def is_external_call(self, call: dict) -> bool:
        """Heuristic to decide if a member call is external-transfer-like."""
        if call.get("type") == "member":
            return call.get("method") in {"call", "transfer", "send"}
        return False
