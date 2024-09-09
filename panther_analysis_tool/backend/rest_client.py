""" Defines a client for a subset of REST API operations. """

from typing import Any, Dict, List

import requests

from panther_analysis_tool.backend.public_api_client import (
    _API_TOKEN_HEADER,
    PublicAPIClient,
)


class APIAccessDeniedError(BaseException):
    def __init__(self, msg: str, endpoint: str):
        self.msg = msg
        self.endpoint = endpoint


class RestAPIClient:
    def __init__(self, gql_client: PublicAPIClient):
        # Construct REST URL
        # mypy thinks this is wrong, but the AIOHTTPTransport does have a url attribute
        gql_url = gql_client._gql_client.transport.url  # type: ignore
        self._url = gql_url.replace("/public/graphql", "")

        # Get API Token
        # Again, mypy is unaware that 'transport' is of type AIOHTTPTransport
        token = gql_client._gql_client.transport.headers[_API_TOKEN_HEADER]  # type: ignore

        self._headers = {_API_TOKEN_HEADER: token, "Content-Type": "application/json"}

    def _get_paginated_results(self, endpoint: str) -> List[Dict[str, Any]]:
        request_params: Dict[str, Any] = {"limit": 100}
        has_more = True
        cursor = ""
        results = []
        while has_more:
            if cursor:
                request_params["cursor"] = cursor
            resp = requests.get(
                self._url + endpoint, headers=self._headers, params=request_params, timeout=20
            )
            # Quickly check for errors
            code = resp.status_code
            if 200 <= code < 300:
                # Request was successsful, continue with the operation
                pass
            elif code == 403:
                # Signal to the calling function that we encountered a permissions error
                raise APIAccessDeniedError(f"Unable to access '{endpoint}'", endpoint)
            else:
                resp.raise_for_status()  # Propagate any unexpected errors
            content = resp.json()
            # Grab cursor for next page of results, if there are more
            if "next" in content:
                cursor = content["next"]
            else:
                has_more = False
            # Get the results
            results += content.get("results", [])
        return results

    def get_analysis_items(self) -> List[Dict[str, Any]]:
        """Returns a list of all the supported Item IDs from the backend."""
        # List of endpoints to fetch from
        endpoints = [
            "/data-models",
            "/globals",
            "/queries",
            "/policies",
            "/rules",
            "/scheduled-rules",
            "/simple-rules",
        ]
        items_from_backend = []
        for endpoint in endpoints:
            results = self._get_paginated_results(endpoint)
            # Add a type field, so we know what kind of item this is
            for result in results:
                # Insert some standardized fields that are useful down the line
                result["_type"] = endpoint
                # Queries are referred to by name in Panther Analysis, but by UUID elsewhere
                result["_id"] = result["name"] if endpoint == "/queries" else result["id"]
            items_from_backend += results
        return items_from_backend
