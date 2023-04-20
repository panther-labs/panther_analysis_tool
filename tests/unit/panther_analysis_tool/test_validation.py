import unittest

from panther_analysis_tool.validation import contains_invalid_table_names


class TestContainsInvalidTableNames(unittest.TestCase):
    def test_complex_sql(self):
        sql = """
        WITH login_attempts as (
          SELECT
              user_name,
              client_ip,
              reported_client_type,
              error_code,
              error_message,
              event_id,
              event_timestamp
            FROM snowflake.account_usage.login_history
            WHERE
              DATEDIFF(HOUR, event_timestamp, CURRENT_TIMESTAMP) < 24
              AND event_type = 'LOGIN'
              AND client_ip != '0.0.0.0' -- filtering out unnecessary 'elided' snowflake entries
          )
          SELECT 
          * 
          FROM login_attempts
          MATCH_RECOGNIZE(
              PARTITION BY client_ip, user_name
              ORDER BY event_timestamp DESC -- backwards in time
              MEASURES
                match_number() as match_number,
                first(event_timestamp) as successful_login_time,
                last(event_timestamp) as start_of_unsuccessful_logins_time,
                count(*) as rows_in_sequence,
                count(row_with_success.*) as num_successes,
                count(row_with_fail.*) as num_fails,
                ARRAY_AGG(DISTINCT error_code) as error_codes,
                ARRAY_AGG(DISTINCT error_message) as error_messages
              ONE ROW PER MATCH
              AFTER MATCH SKIP TO LAST row_with_fail
              -- a success with fails following
              PATTERN(row_with_success row_with_fail+)
              DEFINE
                row_with_success AS error_message is null,
                row_with_fail AS error_message is not null
            )
          HAVING num_fails >= 5 -- changeable per environment
        """
        analysis_spec = {"Query": sql}
        analysis_id = "analysis_id_1"

        output = contains_invalid_table_names(analysis_spec, analysis_id)
        self.assertFalse(output)

    def test_simple_sql(self):
        sql = """SELECT 
               user_name,
               reported_client_type,
               COUNT(event_id) AS counts
               FROM datalake.account_usage.login_history
               WHERE
                DATEDIFF(HOUR, event_timestamp, CURRENT_TIMESTAMP) < 24 
               AND
               error_code IS NOT NULL
               GROUP BY reported_client_type, user_name
               HAVING counts >= 3"""
        analysis_spec = {"Query": sql}
        analysis_id = "analysis_id_1"

        output = contains_invalid_table_names(analysis_spec, analysis_id)
        self.assertTrue(output)