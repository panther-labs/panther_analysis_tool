"""Unit tests for the scheduled_prompt analysis type: schema validation + display label.

Schema coverage focuses on the as-code contract divergences from other types:
- RunAsUser is REQUIRED (execution identity; never the importer/token).
- DisplayName is REQUIRED (no fallback, unlike skills).
- `Private` is NOT a valid field (prompts managed as code are org-shared/public);
  ignore_extra_keys=False rejects it.
"""

import unittest
from typing import Any, Dict

from schema import SchemaError

from panther_analysis_tool.analysis_utils import pretty_analysis_type
from panther_analysis_tool.schemas import SCHEDULED_PROMPT_SCHEMA


def _valid_prompt() -> Dict[str, Any]:
    return {
        "AnalysisType": "scheduled_prompt",
        "PromptName": "weekly_iam_review",
        "DisplayName": "Weekly IAM Review",
        "PromptText": "Summarize new IAM users created this week.",
        "RunAsUser": "alice@example.com",
        "Schedule": {"CronExpression": "0 9 * * 1", "TimeoutMinutes": 10},
    }


class TestScheduledPromptSchema(unittest.TestCase):
    def test_valid_minimal(self) -> None:
        SCHEDULED_PROMPT_SCHEMA.validate(_valid_prompt())

    def test_valid_all_optional_fields(self) -> None:
        prompt = _valid_prompt()
        prompt.update(
            {
                "Description": "A scheduled prompt for unit testing",
                "OutputLength": "largest",
                "Enabled": True,
            }
        )
        SCHEDULED_PROMPT_SCHEMA.validate(prompt)

    def test_valid_rate_schedule(self) -> None:
        prompt = _valid_prompt()
        prompt["Schedule"] = {"RateMinutes": 60, "TimeoutMinutes": 10}
        SCHEDULED_PROMPT_SCHEMA.validate(prompt)

    # --- contract: RunAsUser is required and email-shaped ---
    def test_missing_run_as_user_rejected(self) -> None:
        prompt = _valid_prompt()
        del prompt["RunAsUser"]
        with self.assertRaises(SchemaError):
            SCHEDULED_PROMPT_SCHEMA.validate(prompt)

    def test_run_as_user_must_be_email(self) -> None:
        prompt = _valid_prompt()
        prompt["RunAsUser"] = "not-an-email"
        with self.assertRaises(SchemaError):
            SCHEDULED_PROMPT_SCHEMA.validate(prompt)

    # --- contract: as-code is public; `Private` is not a valid field ---
    def test_private_field_rejected(self) -> None:
        prompt = _valid_prompt()
        prompt["Private"] = True
        with self.assertRaises(SchemaError):
            SCHEDULED_PROMPT_SCHEMA.validate(prompt)

    # --- contract: DisplayName required (no fallback, unlike skills) ---
    def test_missing_display_name_rejected(self) -> None:
        prompt = _valid_prompt()
        del prompt["DisplayName"]
        with self.assertRaises(SchemaError):
            SCHEDULED_PROMPT_SCHEMA.validate(prompt)

    def test_missing_prompt_text_rejected(self) -> None:
        prompt = _valid_prompt()
        del prompt["PromptText"]
        with self.assertRaises(SchemaError):
            SCHEDULED_PROMPT_SCHEMA.validate(prompt)

    def test_invalid_prompt_name_uppercase_rejected(self) -> None:
        prompt = _valid_prompt()
        prompt["PromptName"] = "BadName"
        with self.assertRaises(SchemaError):
            SCHEDULED_PROMPT_SCHEMA.validate(prompt)

    def test_invalid_output_length_rejected(self) -> None:
        prompt = _valid_prompt()
        prompt["OutputLength"] = "huge"
        with self.assertRaises(SchemaError):
            SCHEDULED_PROMPT_SCHEMA.validate(prompt)

    def test_schedule_requires_exactly_one_of_cron_or_rate(self) -> None:
        prompt = _valid_prompt()
        prompt["Schedule"] = {
            "CronExpression": "0 9 * * 1",
            "RateMinutes": 60,
            "TimeoutMinutes": 10,
        }
        with self.assertRaises(SchemaError):
            SCHEDULED_PROMPT_SCHEMA.validate(prompt)

    def test_unknown_field_rejected(self) -> None:
        prompt = _valid_prompt()
        prompt["Bogus"] = "x"
        with self.assertRaises(SchemaError):
            SCHEDULED_PROMPT_SCHEMA.validate(prompt)


class TestPrettyAnalysisTypeScheduledPrompt(unittest.TestCase):
    def test_singular(self) -> None:
        self.assertEqual(pretty_analysis_type("scheduled_prompt"), "Scheduled Prompt")

    def test_plural(self) -> None:
        self.assertEqual(
            pretty_analysis_type("scheduled_prompt", plural=True), "Scheduled Prompts"
        )
