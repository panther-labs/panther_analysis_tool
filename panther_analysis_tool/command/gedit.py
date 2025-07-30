import os
import re


def run() -> None:
    update_alert_context_in_folder(".")


def get_new_function_definition():
    print("Enter the new definition for `alert_context(event)` including any imports.")
    print("End input with EOF\n")

    lines = []
    while True:
        line = input()
        if line.strip() == "EOF" and lines:
            break
        lines.append(line)
    return "\n".join(lines)

def extract_imports_and_function(definition):
    import_lines = []
    function_lines = []

    for line in definition.splitlines():
        if line.strip().startswith("import ") or line.strip().startswith("from "):
            import_lines.append(line)
        else:
            function_lines.append(line)
    
    return import_lines, "\n".join(function_lines).strip()

def detect_indentation_style(text):
    lines = text.splitlines()
    for line in lines:
        if line.startswith("def "):
            idx = lines.index(line)
            # Look for the first indented line after the function definition
            for body_line in lines[idx + 1:]:
                if body_line.strip() == "":
                    continue
                leading = re.match(r'^(\s+)', body_line)
                if leading:
                    return leading.group(1)
    # Default to 4 spaces
    return '    '

def indent_function_body(function_body, indent):
    lines = function_body.strip().splitlines()
    header = lines[0]  # e.g. def alert_context(event):

    body_indent = detect_indentation_style(function_body)

    body_lines = []
    for line in lines[1:]:
        new_line = ""
        while line.startswith(body_indent):
            line = line[len(body_indent):]
            new_line += indent
        body_lines.append(new_line + line)

    indented_body = "\n".join(body_lines)
    return f"{header}\n{indented_body}"

def replace_function_in_file(filepath, function_body, import_lines):
    with open(filepath, 'r', encoding='utf-8') as file:
        content = file.read()

    # Match function `alert_context(event)` and body
    pattern = re.compile(
        r'def alert_context\(event\):\n(?:[ \t]+.*\n?)*',
        re.DOTALL
    )

    match = pattern.search(content)
    if not match:
        print(f"No match found in: {filepath}")
        return

    # Detect indentation style
    indent = detect_indentation_style(content)

    # Re-indent new function to match existing style
    indented_function = indent_function_body(function_body, indent)

    # Replace function definition
    updated_content = pattern.sub(indented_function + '\n', content)

    # Prepend any missing imports
    for import_line in import_lines:
        if import_line not in updated_content:
            updated_content = import_line + "\n" + updated_content

    with open(filepath, 'w', encoding='utf-8') as file:
        file.write(updated_content)

    print(f"Updated: {filepath}")

def update_alert_context_in_folder(folder_path):
    full_def = get_new_function_definition()
    import_lines, function_body = extract_imports_and_function(full_def)

    for root, _, files in os.walk(folder_path):
        for filename in files:
            if filename.endswith('.py'):
                file_path = os.path.join(root, filename)
                replace_function_in_file(file_path, function_body, import_lines)
