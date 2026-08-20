from unittest import TestCase

from panther_analysis_tool.backend.errors import (
    is_retryable_error,
    is_retryable_error_str,
)


class TestIsRetryableErrorStr(TestCase):
    def test_empty_is_not_retryable(self) -> None:
        self.assertFalse(is_retryable_error_str(""))

    def test_transient_conditions_are_retryable(self) -> None:
        # Genuinely transient bulk-upload conditions must stay retryable.
        for err in (
            "another upload is in process",
            "upload failed",
            "ddb lock could not be acquired",
            "upload does not exist",
        ):
            with self.subTest(err=err):
                self.assertTrue(is_retryable_error_str(err))

    def test_generic_bulk_upload_timeout_is_not_retryable(self) -> None:
        # Volume-driven server-side timeout catch-all: deterministic, retrying cannot help.
        # See EPD-6524.
        self.assertFalse(
            is_retryable_error_str("unknown error occurred during bulk upload process")
        )
        self.assertFalse(is_retryable_error_str("unknown error occurred"))


class TestIsRetryableError(TestCase):
    def test_none_is_not_retryable(self) -> None:
        self.assertFalse(is_retryable_error(None))

    def test_matches_message_and_body(self) -> None:
        self.assertTrue(is_retryable_error({"message": "another upload is in process"}))
        self.assertTrue(is_retryable_error({"body": "ddb lock could not be acquired"}))

    def test_generic_bulk_upload_timeout_is_not_retryable(self) -> None:
        self.assertFalse(
            is_retryable_error({"message": "unknown error occurred during bulk upload process"})
        )
