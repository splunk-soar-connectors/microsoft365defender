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

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField, PermissiveActionOutput
from soar_sdk.params import Param, Params

from ..app import Asset, app, get_client
from ..consts import DEFENDER_RUN_QUERY_ENDPOINT
from ..helper import fix_up_odata_fields


class RunQueryParams(Params):
    query: str = Param(description="Query to fetch results", required=True)


class RunQueryEvidenceOutput(ActionOutput):
    odata_type: str | None = OutputField(
        alias="odata_type", example_values=["#test.graph.security.deviceEvidence"]
    )


class RunQueryAdditionalDataOutput(ActionOutput):
    Intent_odata_type: str | None = OutputField(example_values=["#Int64"])


class RunQueryOutput(PermissiveActionOutput):
    DeviceId: str | None = OutputField(
        example_values=["xxxxx9d48ec4859bd94a25039dcba09f4fd9ac78"]
    )
    FileName: str | None = OutputField(example_values=["test.exe"])
    InitiatingProcessFileName: str | None = OutputField(
        example_values=["powershell.exe"]
    )
    Timestamp: str | None = OutputField(example_values=["2022-06-12T04:24:25.0406516Z"])
    odata_context: str | None = OutputField(
        example_values=["https://test.com/v1.0/$metadata/incidents/$entity"]
    )
    additionalData: RunQueryAdditionalDataOutput | None = None
    evidence: list[RunQueryEvidenceOutput] | None = None
    Intent_odata_type: str | None = OutputField(example_values=["#Int64"])


class RunQuerySummary(ActionOutput):
    total_results: int = OutputField(example_values=[1])


@app.action(
    description="An advanced search query",
    action_type="investigate",
    read_only=True,
    render_as="json",
    summary_type=RunQuerySummary,
)
def run_query(
    params: RunQueryParams, soar: SOARClient, asset: Asset
) -> list[RunQueryOutput]:
    client = get_client(asset)

    response = client.make_rest_call(
        DEFENDER_RUN_QUERY_ENDPOINT,
        data=json.dumps({"Query": params.query}),
        method="post",
    )

    results = response.get("results", [])
    outputs = [RunQueryOutput(**fix_up_odata_fields(result)) for result in results]

    soar.set_summary(RunQuerySummary(total_results=len(results)))
    return outputs
