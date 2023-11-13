"""
 Analysis Tool is a command line interface for writing,
testing, and packaging policies/rules.
Copyright (C) 2023 Panther Labs Inc

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

import copy
import logging
from pprint import pformat

from attr import dataclass

from panther_analysis_tool.analysis_utils import LoadAnalysisSpecsResult
from panther_analysis_tool.backend.client import Client as BackendClient
from panther_analysis_tool.backend.client import GenerateEnrichedEventParams
from panther_analysis_tool.constants import AnalysisTypes

TEST_CASE_FIELD_KEY_LOG = "Log"
TEST_CASE_FIELD_KEY_RESOURCE = "Resource"


@dataclass
class EventEnrichmentResult:
    original_test: dict
    enriched_test: dict

    def was_enriched(self) -> bool:
        return self.original_test != self.enriched_test

    def __init__(self, original_test: dict, enriched_test: dict):
        self.original_test = original_test
        self.enriched_test = enriched_test


class EnrichedEventGenerator:
    """Enriches test data for analysis items."""

    def __init__(self, backend: BackendClient):
        """Initializes the TestDataEnricher.

        Args:
            backend: Backend API client.
        """
        self.backend = backend

    @staticmethod
    def _filter_analysis_items(
        analysis_items: list[LoadAnalysisSpecsResult],
    ) -> list[LoadAnalysisSpecsResult]:
        """Filters analysis items to only those that need test data enrichment.

        Args:
            analysis_items: A list of analysis items to filter.

        Returns:
            A list of analysis items that have the Tests property and an AnalysisType of RULE, POLICY, or SCHEDULED_RULE.
        """
        return [
            item
            for item in analysis_items
            if item.analysis_spec.get("Tests")
            and item.analysis_type()
            in [
                AnalysisTypes.RULE,
                AnalysisTypes.POLICY,
                AnalysisTypes.SCHEDULED_RULE,
                AnalysisTypes.CORRELATION_RULE,
            ]
        ]

    # pylint: disable=no-else-return
    @staticmethod
    def _convert_inline_json_dict_to_python_dict(data: dict) -> dict:
        """Converts YAML-loaded inline JSON to Python dictionaries. This allows them
        to be re-serialized into YAML instead of maintaining JSON formatting.
        """
        if isinstance(data, dict):
            new_dict = {}
            for key, value in data.items():
                if isinstance(value, (dict, list)):
                    new_dict[key] = EnrichedEventGenerator._convert_inline_json_dict_to_python_dict(
                        value  # type: ignore
                    )
                else:
                    new_dict[key] = value
            return new_dict
        elif isinstance(data, list):
            new_list = []
            for item in data:
                if isinstance(item, (dict, list)):
                    new_list.append(
                        EnrichedEventGenerator._convert_inline_json_dict_to_python_dict(item)
                    )
                else:
                    new_list.append(item)
            return new_list
        return data

    def _handle_analysis_item(
        self, analysis_id: str, test: dict, test_case_field_key: str
    ) -> EventEnrichmentResult:
        if test_case_field_key not in test:
            logging.error(
                "Skipping test case '%s' for %s, no event data found",
                test["Name"],
                analysis_id,
            )
            return EventEnrichmentResult(test, test)

        params = GenerateEnrichedEventParams(test[test_case_field_key])
        resp = self.backend.generate_enriched_event_input(params)

        if resp.status_code >= 400:
            logging.error(
                "Failed to enrich test data for %s: %s",
                analysis_id,
                resp.data,
            )
            return EventEnrichmentResult(test, test)

        logging.debug("GraphQL Response:\n%s", pformat(resp))

        enriched_test_data = resp.data.enriched_event

        # Create a copy of the existing test data so that we can compare before and after.
        enriched_test = copy.deepcopy(test)

        # We're only copying the p_enrichment field because it's the only net-new
        # field. This helps reduce unnecessary deserialize/serialize noise.
        #
        # If the returned "enriched event" has a p_enrichment field that's empty,
        # we'll just skip it. This reduces git diff noise.
        p_enrichment = enriched_test_data.get("p_enrichment", {})
        if p_enrichment in [{}, None]:
            logging.warning(
                "Skipping test case '%s' for %s, no enrichment data found",
                test["Name"],
                analysis_id,
            )
            # We're returning (test, enriched_test), but they're identical in content here.
            # We push enriched_test through _convert_inline_json_dict_to_python_dict so that
            # we can clean up the inline JSON content. Otherwise, it'll format as flow-style
            # inline JSON block in the YAML.
            return EventEnrichmentResult(
                test, EnrichedEventGenerator._convert_inline_json_dict_to_python_dict(enriched_test)
            )

        # Some test cases are pasted in as JSON. JSON does not roundtrip
        # nicely - often just rendering as one giant line after we add
        # the p_enrichment field.
        #
        # We're forcibly converting the test case data to a Python dict
        # so that it roundtrips out as YAML instead. This is noisy
        # for those tests that are in JSON format, but it's preferable
        # to the alternative.
        enriched_test[test_case_field_key] = enriched_test_data
        enriched_test = EnrichedEventGenerator._convert_inline_json_dict_to_python_dict(
            enriched_test
        )

        return EventEnrichmentResult(test, enriched_test)

    def _handle_rule_test(self, analysis_id: str, test: dict) -> EventEnrichmentResult:
        return self._handle_analysis_item(analysis_id, test, TEST_CASE_FIELD_KEY_LOG)

    def _handle_policy_test(self, analysis_id: str, test: dict) -> EventEnrichmentResult:
        return self._handle_analysis_item(analysis_id, test, TEST_CASE_FIELD_KEY_RESOURCE)

    def enrich_test_data(
        self, analysis_items: list[LoadAnalysisSpecsResult]
    ) -> list[LoadAnalysisSpecsResult]:
        """Enriches test data for analysis items.

        Args:
            analysis_items: A list of analysis items to enrich test data for.
        """
        logging.debug("Received %s analysis items", len(analysis_items))

        # Enrich any detections
        relevant_analysis_items = EnrichedEventGenerator._filter_analysis_items(analysis_items)
        logging.info(
            "Enriching test data for %s detections, after filtering", len(relevant_analysis_items)
        )

        enriched_analysis_items = []

        for analysis_item in relevant_analysis_items:
            analysis_id = analysis_item.analysis_spec.get(
                "RuleID"
            ) or analysis_item.analysis_spec.get("PolicyID")

            analysis_type = analysis_item.analysis_id()
            logging.info("Processing %s '%s'", analysis_type, analysis_id)
            tests = analysis_item.analysis_spec.get("Tests")

            results: list[EventEnrichmentResult] = []

            for test in tests:
                logging.info("Enriching test case '%s' for %s", test["Name"], analysis_id)
                if "Log" in test:
                    event_enrichment_result = self._handle_rule_test(analysis_id, test)
                elif "Resource" in test:
                    event_enrichment_result = self._handle_policy_test(analysis_id, test)
                else:
                    logging.warning(
                        "Skipping test case '%s' for %s, no event data found",
                        test["Name"],
                        analysis_id,
                    )

                results.append(event_enrichment_result)

            logging.debug("Enrichment results:\n%s", pformat(results))

            if any(result.was_enriched() for result in results):
                analysis_item.analysis_spec["Tests"] = [result.enriched_test for result in results]
                analysis_item.serialize_to_file()
                enriched_analysis_items.append(analysis_item)
            else:
                logging.info("No test data enrichment available for rule '%s'", analysis_id)

        return enriched_analysis_items
