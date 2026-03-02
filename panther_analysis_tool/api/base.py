"""Base class for analysis item wrappers with Python code manipulation."""

import ast
import re
from abc import ABC, abstractmethod
from typing import Any

from panther_analysis_tool import analysis_utils


class BaseAnalysisItem(ABC):
    """Base class for all analysis item wrappers.

    Users cannot directly access the underlying YAML or Python code.
    All access must go through properties and methods.
    """

    _item: analysis_utils.AnalysisItem

    def __init__(self, item: analysis_utils.AnalysisItem):
        self._item = item

    # Properties (read-only)
    @property
    def id(self) -> str:
        """Get the analysis ID."""
        return self._item.analysis_id()

    @property
    def analysis_type(self) -> str:
        """Get the analysis type."""
        return self._item.analysis_type()

    # Internal helper methods for field access
    def _set_field(self, field: str, value: Any) -> None:
        """Internal method to set a YAML field value."""
        self._item.yaml_file_contents[field] = value

    def _get_field(self, field: str, default: Any = None) -> Any:
        """Internal method to get a YAML field value."""
        return self._item.yaml_file_contents.get(field, default)

    def _remove_field(self, field: str) -> None:
        """Internal method to remove a YAML field."""
        if field in self._item.yaml_file_contents:
            del self._item.yaml_file_contents[field]

    # Python code manipulation (fine-grained, no direct access)
    def add_import(self, import_stmt: str) -> None:
        """Add an import statement to the Python code.

        Args:
            import_stmt: Import statement (e.g., "from panther_base import something"
                        or "import json")
        """
        if self._item.python_file_contents is None:
            raise ValueError("This analysis item does not have a Python file")

        code = self._item.python_file_contents.decode("utf-8")
        new_code = self._add_import_to_code(code, import_stmt)
        self._item.python_file_contents = new_code.encode("utf-8")

    def remove_import(self, module_name: str) -> None:
        """Remove an import statement from the Python code.

        Args:
            module_name: Name of the module to remove (e.g., "json", "panther_base")
        """
        if self._item.python_file_contents is None:
            raise ValueError("This analysis item does not have a Python file")

        code = self._item.python_file_contents.decode("utf-8")
        new_code = self._remove_import_from_code(code, module_name)
        self._item.python_file_contents = new_code.encode("utf-8")

    def add_function(self, function_name: str, function_body: str) -> None:
        """Add a new function to the Python code.

        Args:
            function_name: Name of the function (e.g., "helper_function")
            function_body: Complete function definition including signature and body
        """
        if self._item.python_file_contents is None:
            raise ValueError("This analysis item does not have a Python file")

        code = self._item.python_file_contents.decode("utf-8")
        new_code = self._add_function_to_code(code, function_name, function_body)
        self._item.python_file_contents = new_code.encode("utf-8")

    def remove_function(self, function_name: str) -> None:
        """Remove a function from the Python code.

        Args:
            function_name: Name of the function to remove
        """
        if self._item.python_file_contents is None:
            raise ValueError("This analysis item does not have a Python file")

        code = self._item.python_file_contents.decode("utf-8")
        new_code = self._remove_function_from_code(code, function_name)
        self._item.python_file_contents = new_code.encode("utf-8")

    def get_function(self, function_name: str) -> str | None:
        """Get a function's code from the Python file.

        Args:
            function_name: Name of the function (e.g., "rule", "severity")

        Returns:
            Function code as string, or None if not found
        """
        if self._item.python_file_contents is None:
            return None

        code = self._item.python_file_contents.decode("utf-8")
        return self._extract_function_from_code(code, function_name)

    # Detection-specific Python manipulation
    def add_severity_function(self, severity_body: str) -> None:
        """Add or replace the severity function for rules/policies.

        Args:
            severity_body: Complete severity function body
        """
        if self._item.python_file_contents is None:
            raise ValueError("This analysis item does not have a Python file")

        code = self._item.python_file_contents.decode("utf-8")
        new_code = self._add_or_replace_function(code, "severity", severity_body)
        self._item.python_file_contents = new_code.encode("utf-8")

    def remove_severity_function(self) -> None:
        """Remove the severity function if it exists."""
        self.remove_function("severity")

    # Type-specific methods (to be overridden)
    @property
    @abstractmethod
    def display_name(self) -> str | None:
        """Get the display name."""

    @display_name.setter
    @abstractmethod
    def display_name(self, value: str) -> None:
        """Set the display name."""

    # Internal Python manipulation helpers
    def _add_import_to_code(self, code: str, import_stmt: str) -> str:
        """Add an import statement to the code, placing it after existing imports."""
        try:
            tree = ast.parse(code)
        except SyntaxError:
            # If code is malformed, just prepend the import
            return f"{import_stmt}\n{code}"

        # Find the last import statement
        last_import_line = 0
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                if hasattr(node, "lineno"):
                    last_import_line = max(last_import_line, node.lineno)

        if last_import_line > 0:
            lines = code.split("\n")
            # Insert after the last import
            lines.insert(last_import_line, import_stmt)
            return "\n".join(lines)
        else:
            # No imports found, add at the beginning
            return f"{import_stmt}\n{code}"

    def _remove_import_from_code(self, code: str, module_name: str) -> str:
        """Remove import statements matching the module name."""
        try:
            tree = ast.parse(code)
        except SyntaxError:
            # If code is malformed, use regex fallback
            return self._remove_import_regex(code, module_name)

        lines = code.split("\n")
        lines_to_remove = set()

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] == module_name:
                        if hasattr(node, "lineno"):
                            lines_to_remove.add(node.lineno - 1)
            elif isinstance(node, ast.ImportFrom):
                if node.module and node.module.split(".")[0] == module_name:
                    if hasattr(node, "lineno"):
                        lines_to_remove.add(node.lineno - 1)

        # Remove lines in reverse order to maintain indices
        for line_num in sorted(lines_to_remove, reverse=True):
            if 0 <= line_num < len(lines):
                del lines[line_num]

        return "\n".join(lines)

    def _remove_import_regex(self, code: str, module_name: str) -> str:
        """Fallback regex-based import removal."""
        pattern = re.compile(
            rf"^(from\s+{re.escape(module_name)}\s+import|import\s+{re.escape(module_name)}).*$",
            re.MULTILINE,
        )
        return pattern.sub("", code).strip()

    def _add_function_to_code(self, code: str, function_name: str, function_body: str) -> str:
        """Add a function to the code before the main function (rule/policy)."""
        # Check if function already exists
        if self._function_exists(code, function_name):
            raise ValueError(f"Function '{function_name}' already exists")

        # Find insertion point (before rule/policy function)
        main_functions = ["rule", "policy"]
        insertion_line = len(code.split("\n"))

        for main_func in main_functions:
            pos = code.find(f"def {main_func}(")
            if pos != -1:
                insertion_line = code[:pos].count("\n")
                break

        lines = code.split("\n")
        lines.insert(insertion_line, function_body)
        return "\n".join(lines)

    def _remove_function_from_code(self, code: str, function_name: str) -> str:
        """Remove a function definition from the code."""
        try:
            tree = ast.parse(code)
        except SyntaxError:
            # Fallback to regex
            return self._remove_function_regex(code, function_name)

        lines = code.split("\n")
        lines_to_remove = set()

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == function_name:
                start_line = node.lineno - 1
                end_line = node.end_lineno if hasattr(node, "end_lineno") else start_line
                lines_to_remove.update(range(start_line, end_line + 1))

        # Remove lines in reverse order
        for line_num in sorted(lines_to_remove, reverse=True):
            if 0 <= line_num < len(lines):
                del lines[line_num]

        return "\n".join(lines)

    def _remove_function_regex(self, code: str, function_name: str) -> str:
        """Fallback regex-based function removal."""
        pattern = re.compile(
            rf"^def\s+{re.escape(function_name)}\s*\([^)]*\):.*?(?=^def\s|\Z)",
            re.MULTILINE | re.DOTALL,
        )
        return pattern.sub("", code).strip()

    def _extract_function_from_code(self, code: str, function_name: str) -> str | None:
        """Extract a function's code as a string."""
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return None

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == function_name:
                lines = code.split("\n")
                start_line = node.lineno - 1
                end_line = node.end_lineno if hasattr(node, "end_lineno") else start_line
                return "\n".join(lines[start_line : end_line + 1])

        return None

    def _add_or_replace_function(self, code: str, function_name: str, function_body: str) -> str:
        """Add or replace a function in the code."""
        if self._function_exists(code, function_name):
            code = self._remove_function_from_code(code, function_name)
        return self._add_function_to_code(code, function_name, function_body)

    def _function_exists(self, code: str, function_name: str) -> bool:
        """Check if a function exists in the code."""
        try:
            tree = ast.parse(code)
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef) and node.name == function_name:
                    return True
        except SyntaxError:
            pass
        return False

    def _append_to_function(self, function_name: str, code_to_append: str) -> None:
        """Append code to a function's body."""
        if self._item.python_file_contents is None:
            raise ValueError("This analysis item does not have a Python file")

        code = self._item.python_file_contents.decode("utf-8")
        func_code = self._extract_function_from_code(code, function_name)
        if func_code is None:
            raise ValueError(f"Function '{function_name}' not found")

        # Find the last return statement or end of function
        lines = func_code.split("\n")
        indent = self._get_indent(lines[0])

        # Append before the last line (closing)
        append_indent = indent + "    "
        append_lines = [append_indent + line for line in code_to_append.split("\n")]

        lines.insert(-1, "\n".join(append_lines))
        new_func_code = "\n".join(lines)

        # Replace the function in the code
        new_code = code.replace(func_code, new_func_code)
        self._item.python_file_contents = new_code.encode("utf-8")

    def _prepend_to_function(self, function_name: str, code_to_prepend: str) -> None:
        """Prepend code to a function's body."""
        if self._item.python_file_contents is None:
            raise ValueError("This analysis item does not have a Python file")

        code = self._item.python_file_contents.decode("utf-8")
        func_code = self._extract_function_from_code(code, function_name)
        if func_code is None:
            raise ValueError(f"Function '{function_name}' not found")

        lines = func_code.split("\n")
        indent = self._get_indent(lines[0])

        # Find the first line of the function body (after def line)
        body_start = 1
        while body_start < len(lines) and not lines[body_start].strip():
            body_start += 1

        prepend_indent = indent + "    "
        prepend_lines = [prepend_indent + line for line in code_to_prepend.split("\n")]

        lines.insert(body_start, "\n".join(prepend_lines))
        new_func_code = "\n".join(lines)

        # Replace the function in the code
        new_code = code.replace(func_code, new_func_code)
        self._item.python_file_contents = new_code.encode("utf-8")

    def _get_indent(self, line: str) -> str:
        """Get the indentation of a line."""
        return line[: len(line) - len(line.lstrip())]
