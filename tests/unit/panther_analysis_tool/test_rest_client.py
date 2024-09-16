""" Some tests to make sure the REST API client works properly. May have more tests in future. """

import contextlib
import io
from unittest import mock

from pyfakefs.fake_filesystem_unittest import Pause, TestCase

from panther_analysis_tool import main as pat
from panther_analysis_tool.backend.public_api_client import PublicAPIClient, PublicAPIClientOptions

class MockResp:
    """ Fake HTTP Response object. """
    def __init__(self, status_code, data={}):
        self.status_code = status_code
        self.data = data

    def json(self):
        return self.data  # Simulates empty list returned

class TestRestAPI(TestCase):
    def test_pagination(self):
        """ This test ensures that when the client receives a pagination token, it properly
        appends it to the next API request. """
        request_count = 0 # Number of times the endpoint has been requested
        token_str = "token" # Sample pagination token
        def mocked_get(endpoint, headers={}, params={}, timeout=0):
            def get(endpoint, headers, params, *args, **kwargs):
                request_count += 1 # keep track of number of requests
                if request_count == 1:
                    # Add a pagination token to response
                    return MockResp(200, {
                        "next": token_str,
                        "results": []
                    })
                # if requests > 1, validate cursor
                self.assertEqual(params["cursor"], token_str)
                # Return stuff
                return MockResp(200, {
                    "results": []
                })

        # We patch the HTTP get reqeuest, and the local analysis scan. (The local scan is not
        #   part of this test, so we have it just return empty.)
        @mock.patch("requests.get", mocked_get("/data-models"))
        @mock.patch("panther_analysis_tool.command.upload_sync._get_analysis_ids", lambda _: [])
        def test():
            with contextlib.redirect_stdout(io.StringIO()):  # for better test output
                # Create a fake client, which is used to instantiate the REST API client
                client = PublicAPIClient(
                    PublicAPIClientOptions(
                        host="example.runpanther.net", token="token", user_id=""
                    )
                )
                # Run "pat upload --sync" and record results
                with Pause(self.fs):
                    args = pat.setup_parser().parse_args(("upload", "--sync"))
                    return_code, _ = pat.upload_analysis(client, args)
                # The assertion is in the mocked get fyunction, so if this completes and returns
                #   a 0 code, the test passes
                self.assetEqual(return_code, 0)

        test()  # Run the test function above