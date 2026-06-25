"""Unit tests for the scheduled_prompt analysis type: schema validation + display label.

Schema coverage focuses on the as-code contract divergences from other types:
- RunAsUser is REQUIRED and polymorphic (a user email OR an API-token id); format is
  resolved server-side, so locally only non-empty is enforced.
- DisplayName is REQUIRED (no fallback, unlike skills).
- Bulk upload is shared-only: `Private: false`/omitted is accepted; `Private: true` rejected.
"""

import unittest
from typing import Any, Dict

from schema import SchemaError

from panther_analysis_tool.analysis_utils import pretty_analysis_type
from panther_analysis_tool.core.definitions import (
    ClassifiedAnalysis,
    ClassifiedAnalysisContainer,
)
from panther_analysis_tool.schemas import SCHEDULED_PROMPT_SCHEMA
from panther_analysis_tool.validation import validate_packs


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

    # --- contract: RunAsUser is required; polymorphic (a user email OR a po_ token id) ---
    def test_missing_run_as_user_rejected(self) -> None:
        prompt = _valid_prompt()
        del prompt["RunAsUser"]
        with self.assertRaises(SchemaError):
            SCHEDULED_PROMPT_SCHEMA.validate(prompt)

    def test_empty_run_as_user_rejected(self) -> None:
        prompt = _valid_prompt()
        prompt["RunAsUser"] = ""
        with self.assertRaises(SchemaError):
            SCHEDULED_PROMPT_SCHEMA.validate(prompt)

    def test_run_as_user_accepts_api_token_id(self) -> None:
        # The backend accepts a po_ API-token id as the run-as identity; a strict email
        # regex would wrongly reject it. Format/existence is validated server-side.
        prompt = _valid_prompt()
        prompt["RunAsUser"] = "po_abc123def456"
        SCHEDULED_PROMPT_SCHEMA.validate(prompt)

    # --- contract: shared-only — Private:false/omitted accepted, Private:true rejected ---
    def test_private_true_rejected(self) -> None:
        prompt = _valid_prompt()
        prompt["Private"] = True
        with self.assertRaises(SchemaError):
            SCHEDULED_PROMPT_SCHEMA.validate(prompt)

    def test_private_false_accepted(self) -> None:
        prompt = _valid_prompt()
        prompt["Private"] = False
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


class TestValidatePacksWithScheduledPrompt(unittest.TestCase):
    """validate_packs iterates ALL classified specs, including scheduled prompts, which
    carry only a PromptName (none of the other ID fields). The ID-lookup chain must use
    PromptName and never fall back to a bare subscript — otherwise a prompt alongside a
    pack raises KeyError and crashes every test/validate run that includes one."""

    @staticmethod
    def _prompt(name: str) -> ClassifiedAnalysis:
        return ClassifiedAnalysis(
            f"{name}.yml", ".", {"AnalysisType": "scheduled_prompt", "PromptName": name}
        )

    def test_prompt_only_container_does_not_crash(self) -> None:
        container = ClassifiedAnalysisContainer()
        container.scheduled_prompts.append(self._prompt("weekly_iam_review"))
        self.assertEqual(validate_packs(container), [])  # no KeyError, no invalid packs

    def test_prompt_is_indexed_by_prompt_name_for_pack_membership(self) -> None:
        container = ClassifiedAnalysisContainer()
        container.scheduled_prompts.append(self._prompt("weekly_iam_review"))
        container.packs.append(
            ClassifiedAnalysis(
                "pack.yml",
                ".",
                {
                    "AnalysisType": "pack",
                    "PackID": "iam_pack",
                    "PackDefinition": {"IDs": ["weekly_iam_review"]},
                },
            )
        )
        # The prompt resolves by PromptName, so the pack reference is valid.
        self.assertEqual(validate_packs(container), [])

    def test_pack_referencing_missing_prompt_is_reported(self) -> None:
        container = ClassifiedAnalysisContainer()
        container.scheduled_prompts.append(self._prompt("weekly_iam_review"))
        container.packs.append(
            ClassifiedAnalysis(
                "pack.yml",
                ".",
                {
                    "AnalysisType": "pack",
                    "PackID": "iam_pack",
                    "PackDefinition": {"IDs": ["nonexistent_prompt"]},
                },
            )
        )
        invalid = validate_packs(container)
        self.assertEqual(len(invalid), 1)
        self.assertIn("nonexistent_prompt", invalid[0][1])
