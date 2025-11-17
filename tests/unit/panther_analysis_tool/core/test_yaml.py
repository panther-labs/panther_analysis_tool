import io

from panther_analysis_tool.core import yaml


def test_block_style_yaml() -> None:
    input = """Thing: thing
Thing2: "thing2"
Thing3: [thing3, thing4, "thing5", {"thing6": "thing7"}]
Thing4: {thing4: this, this: {thing5: thing6}, that: [thing7, thing8]}
Thing5: {
    thing5: thing6,
    "thing7": "thing8"
}
Thing6: 'thing6'
Thing7: 7
Thing8: true
Thing9: false
Thing10: null
Thing11: [
    "thing11",
    "thing12",
    {"thing13": "thing14"},
    [thing15, thing16]
]
Thing12: 
    Thing12: Thing13
    Thing14:
        Thing14: Thing15
        Thing16: Thing17
    Thing18: 
        - Thing19
        - Thing20
Thing13:
  - Thing:Thing
  - Thing:Thing
A: do not move me
    """

    expected = """Thing: thing
Thing2: "thing2"
Thing3:
  - thing3
  - thing4
  - "thing5"
  - "thing6": "thing7"
Thing4:
  thing4: this
  this:
    thing5: thing6
  that:
    - thing7
    - thing8
Thing5:
  thing5: thing6
  "thing7": "thing8"
Thing6: 'thing6'
Thing7: 7
Thing8: true
Thing9: false
Thing10:
Thing11:
  - "thing11"
  - "thing12"
  - "thing13": "thing14"
  -   - thing15
      - thing16
Thing12:
  Thing12: Thing13
  Thing14:
    Thing14: Thing15
    Thing16: Thing17
  Thing18:
    - Thing19
    - Thing20
Thing13:
  - Thing:Thing
  - Thing:Thing
A: do not move me
"""

    loaded = yaml.BlockStyleYAML().load(input)

    out = io.StringIO()
    yaml.BlockStyleYAML().dump(loaded, out)
    result = out.getvalue()

    if result != expected:
        result_lines = result.split("\n")
        expected_lines = expected.split("\n")
        # print the lines so that is looks like you are viewing two files side by side
        for i in range(min(len(result_lines), len(expected_lines))):
            padding = " " * (40 - len(result_lines[i]))
            if result_lines[i] != expected_lines[i]:
                # print the lines in red
                result_lines[i] = f"\033[91m{result_lines[i]}\033[0m"
                expected_lines[i] = f"\033[91m{expected_lines[i]}\033[0m"
            result_line = result_lines[i] + padding
            print(f"{result_line}{expected_lines[i]}")

    assert result == expected
