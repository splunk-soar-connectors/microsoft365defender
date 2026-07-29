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
from soar_sdk.action_results import OutputField, PermissiveActionOutput
from soar_sdk.params import Param, Params

from ..app import Asset, app, get_client
from ..consts import (
    DEFENDER_INCIDENT_ID_ENDPOINT,
    DEFENDER_SUCCESSFULLY_RETRIEVED_INCIDENT,
)
from ..helper import encode_graph_path_segment, fix_up_odata_fields
from .list_incidents import IncidentCommentOutput, render_display_incidents


class GetIncidentParams(Params):
    incident_id: str = Param(
        description="ID of the incident to retrieve",
        required=True,
        primary=True,
        cef_types=["defender incident id"],
    )


class GetIncidentOutput(PermissiveActionOutput):
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
    tags: list[str] | None = None
    tenantId: str | None = OutputField(cef_types=["microsoft tenantid"])
    summary: str | None = OutputField()
    description: str | None = OutputField()
    odata_context: str | None = OutputField()
    lastModifiedBy: str | None = OutputField()
    resolvingComment: str | None = OutputField()
    odata_context_raw: str | None = OutputField(alias="@odata.context")


@app.action(
    description="Retrieve the properties and relationships of an incident object",
    action_type="investigate",
    read_only=True,
    view_handler=render_display_incidents,
)
def get_incident(
    params: GetIncidentParams, soar: SOARClient, asset: Asset
) -> list[GetIncidentOutput]:
    client = get_client(asset)

    endpoint = DEFENDER_INCIDENT_ID_ENDPOINT.format(
        input=encode_graph_path_segment(params.incident_id)
    )
    response = client.make_rest_call(endpoint)

    soar.set_message(DEFENDER_SUCCESSFULLY_RETRIEVED_INCIDENT)
    return [GetIncidentOutput(**fix_up_odata_fields(response))]
