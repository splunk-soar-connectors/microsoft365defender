# Copyright (c) 2022-2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.

import json

import requests
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger
from soar_sdk.params import MakeRequestParams, Param

from ..app import Asset, app, get_client
from ..consts import DEFENDER_MSGRAPH_API_BASE_URL

logger = getLogger()


class DefenderMakeRequestParams(MakeRequestParams):
    endpoint: str = Param(
        description=(
            "Microsoft Graph API endpoint to call, appended to the base URL "
            "(https://graph.microsoft.com/v1.0). Example: '/security/alerts_v2'"
        ),
        required=True,
    )
    verify_ssl: bool = Param(
        description="Whether to verify the SSL certificate.",
        required=False,
        default=True,
    )


class DefenderMakeRequestOutput(ActionOutput):
    status_code: int = OutputField(example_values=[200])
    response_body: str = OutputField(example_values=['{"value": []}'])

    @classmethod
    def from_response(cls, response: requests.Response) -> "DefenderMakeRequestOutput":
        return cls(status_code=response.status_code, response_body=response.text)


@app.make_request()
def http_action(
    params: DefenderMakeRequestParams, asset: Asset
) -> DefenderMakeRequestOutput:
    if params.endpoint.startswith(("http://", "https://")):
        raise ActionFailure(
            f"Invalid endpoint: {params.endpoint}. Do not include the base URL — "
            "it is derived from the Microsoft Graph API base (https://graph.microsoft.com/v1.0)."
        )

    client = get_client(asset)

    endpoint = (
        params.endpoint if params.endpoint.startswith("/") else f"/{params.endpoint}"
    )
    url = f"{DEFENDER_MSGRAPH_API_BASE_URL}{endpoint}"

    headers: dict = {
        "Authorization": f"Bearer {client.access_token()}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    if params.headers:
        try:
            headers.update(json.loads(params.headers))
        except (json.JSONDecodeError, TypeError) as e:
            raise ActionFailure(f"Invalid JSON headers: {params.headers}") from e

    query_params = None
    if params.query_parameters:
        try:
            query_params = json.loads(params.query_parameters)
        except (json.JSONDecodeError, TypeError):
            query_string = params.query_parameters.lstrip("?")
            url = f"{url}?{query_string}" if "?" not in url else f"{url}&{query_string}"

    body = None
    json_body = None
    if params.body:
        content_type = headers.get("Content-Type", "").lower()
        if "json" in content_type:
            try:
                json_body = json.loads(params.body)
            except (json.JSONDecodeError, TypeError) as e:
                raise ActionFailure(f"Invalid JSON body: {params.body}") from e
        else:
            body = params.body

    timeout = params.timeout or client._timeout

    try:
        response = requests.request(
            method=params.http_method,
            url=url,
            headers=headers,
            params=query_params,
            data=body,
            json=json_body,
            timeout=timeout,
            verify=params.verify_ssl,
        )
    except Exception as e:
        raise ActionFailure(f"Request failed: {e}") from e

    return DefenderMakeRequestOutput.from_response(response)
