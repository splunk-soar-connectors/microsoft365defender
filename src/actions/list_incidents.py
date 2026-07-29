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

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField, PermissiveActionOutput
from soar_sdk.params import Param, Params

from ..app import Asset, app, get_client
from ..consts import (
    DEFENDER_INCIDENT_DEFAULT_LIMIT,
    DEFENDER_INCIDENT_DEFAULT_OFFSET,
    DEFENDER_LIMIT_KEY,
    DEFENDER_LIST_INCIDENTS_ENDPOINT,
    DEFENDER_OFFSET_KEY,
)
from ..helper import fix_up_odata_fields, validate_integer


class ListIncidentsParams(Params):
    limit: int = Param(
        description="Maximum number of incidents to return",
        required=False,
        default=DEFENDER_INCIDENT_DEFAULT_LIMIT,
    )
    offset: int = Param(
        description="Number of incidents to skip",
        required=False,
        default=DEFENDER_INCIDENT_DEFAULT_OFFSET,
    )
    filter: str = Param(
        description="Filter incidents based on property",
        required=False,
    )
    orderby: str = Param(
        description="Order results based on property",
        required=False,
    )


class IncidentCommentOutput(ActionOutput):
    comment: str | None = OutputField()
    createdByDisplayName: str | None = OutputField()
    createdDateTime: str | None = OutputField()


class ListIncidentsOutput(PermissiveActionOutput):
    assignedTo: str | None = OutputField(cef_types=["email"])
    classification: str | None = OutputField()
    comments: list[IncidentCommentOutput] | None = None
    createdDateTime: str | None = OutputField()
    determination: str | None = OutputField()
    displayName: str | None = OutputField()
    id: str | None = OutputField(cef_types=["defender incident id"])
    incidentWebUrl: str | None = OutputField(cef_types=["url"])
    lastUpdateDateTime: str | None = OutputField()
    redirectIncidentId: str | None = OutputField(cef_types=["defender incident id"])
    severity: str | None = OutputField(cef_types=["defender severity"])
    status: str | None = OutputField()
    tenantId: str | None = OutputField()
    summary: str | None = OutputField()
    description: str | None = OutputField()
    lastModifiedBy: str | None = OutputField()
    resolvingComment: str | None = OutputField()


class ListIncidentsSummary(ActionOutput):
    total_incidents: int = OutputField(example_values=[10])


@app.view_handler(template="microsoft365defender_list_incidents.html")
def render_display_incidents(outputs: list[ListIncidentsOutput]) -> dict:
    data = [o.model_dump() for o in outputs]
    return {
        "results": [
            {"data": data, "param": {}, "summary": {"total_incidents": len(data)}}
        ]
    }


@app.action(
    description="Get the list of recent incidents",
    action_type="investigate",
    read_only=True,
    view_handler=render_display_incidents,
    summary_type=ListIncidentsSummary,
)
def list_incidents(
    params: ListIncidentsParams, soar: SOARClient, asset: Asset
) -> list[ListIncidentsOutput]:
    client = get_client(asset)

    limit = validate_integer(params.limit, DEFENDER_LIMIT_KEY, allow_zero=False)
    offset = validate_integer(params.offset, DEFENDER_OFFSET_KEY)

    incident_list = client.paginator(
        DEFENDER_LIST_INCIDENTS_ENDPOINT, limit, offset, params.filter, params.orderby
    )

    outputs = [
        ListIncidentsOutput(**fix_up_odata_fields(incident))
        for incident in incident_list
    ]

    soar.set_summary(ListIncidentsSummary(total_incidents=len(outputs)))
    return outputs
