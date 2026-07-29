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
from soar_sdk.action_results import OutputField, PermissiveActionOutput
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import Param, Params

from ..app import Asset, app, get_client
from ..consts import (
    DEFENDER_INCIDENT_ID_ENDPOINT,
    DEFENDER_INCIDENT_KEYS_MAPPING,
    DEFENDER_INCIDENT_NO_PARAMETER_PROVIDED,
    DEFENDER_INCIDENT_PARAMS_MAPPING,
    DEFENDER_INCIDENT_UPDATED_SUCCESSFULLY,
    DEFENDER_INVALID_INCIDENT_INPUT,
    DEFENDER_UPDATE_INCIDENT_DETERMINATION_DICT,
    DEFENDER_UPDATE_INCIDENT_STATUS_DICT,
)
from ..helper import fix_up_odata_fields


class UpdateIncidentParams(Params):
    incident_id: str = Param(
        description="ID of the incident to update",
        required=True,
        primary=True,
        cef_types=["defender incident id"],
    )
    status: str = Param(
        description="Specify the current status of the incident",
        required=False,
        value_list=list(DEFENDER_UPDATE_INCIDENT_STATUS_DICT.keys()),
    )
    assign_to: str = Param(
        description="Owner of the incident",
        required=False,
    )
    classification: str = Param(
        description="Specification of the incident",
        required=False,
        value_list=[
            "Unknown",
            "False Positive",
            "True Positive",
            "Informational, expected activity",
            "Unknown Future Value",
        ],
    )
    determination: str = Param(
        description="Specifies the determination of the incident",
        required=False,
        value_list=list(DEFENDER_UPDATE_INCIDENT_DETERMINATION_DICT.keys()),
    )


class UpdateIncidentOutput(PermissiveActionOutput):
    assignedTo: str | None = OutputField(cef_types=["email"])
    classification: str | None = OutputField()
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


@app.view_handler(template="microsoft365defender_update_incident.html")
def render_update_incident(outputs: list[UpdateIncidentOutput]) -> dict:
    data = [o.model_dump() for o in outputs]
    return {"results": [{"data": data, "param": {}, "summary": {}}]}


@app.action(
    description="Update the properties of an incident object",
    action_type="generic",
    read_only=False,
    view_handler=render_update_incident,
)
def update_incident(
    params: UpdateIncidentParams, soar: SOARClient, asset: Asset
) -> list[UpdateIncidentOutput]:
    client = get_client(asset)

    inputs = {
        "assign_to": params.assign_to,
        "status": params.status,
        "classification": params.classification,
        "determination": params.determination,
    }

    if not any(inputs.values()):
        raise ActionFailure(DEFENDER_INCIDENT_NO_PARAMETER_PROVIDED)

    request_body = {}
    for param_name, value in inputs.items():
        if not value:
            continue

        mapped_value = value
        if param_name in DEFENDER_INCIDENT_PARAMS_MAPPING:
            if value not in DEFENDER_INCIDENT_PARAMS_MAPPING[param_name]:
                raise ActionFailure(DEFENDER_INVALID_INCIDENT_INPUT.format(param_name))
            mapped_value = DEFENDER_INCIDENT_PARAMS_MAPPING[param_name][value]

        key = DEFENDER_INCIDENT_KEYS_MAPPING.get(param_name, param_name)
        request_body[key] = mapped_value

    endpoint = DEFENDER_INCIDENT_ID_ENDPOINT.format(input=params.incident_id)
    response = client.make_rest_call(
        endpoint, data=json.dumps(request_body), method="patch"
    )

    soar.set_message(DEFENDER_INCIDENT_UPDATED_SUCCESSFULLY)
    return [UpdateIncidentOutput(**fix_up_odata_fields(response))]
