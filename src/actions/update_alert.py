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
    DEFENDER_ALERT_UPDATED_SUCCESSFULLY,
    DEFENDER_ALERTS_ID_ENDPOINT,
    DEFENDER_INVALID_CLASSIFICATION,
    DEFENDER_INVALID_DETERMINATION,
    DEFENDER_INVALID_STATUS,
    DEFENDER_JSON_CLASSIFICATION,
    DEFENDER_JSON_DETERMINATION,
    DEFENDER_JSON_STATUS,
    DEFENDER_NO_PARAMETER_PROVIDED,
    DEFENDER_RESPONSE_ASSIGNED_TO,
    DEFENDER_UPDATE_ALERT_CLASSIFICATION_DICT,
    DEFENDER_UPDATE_ALERT_DETERMINATION_DICT,
    DEFENDER_UPDATE_ALERT_STATUS_DICT,
)
from ..helper import fix_up_odata_fields


class UpdateAlertParams(Params):
    alert_id: str = Param(
        description="ID of the alert",
        required=True,
        primary=True,
        cef_types=["defender alert id"],
    )
    status: str = Param(
        description="Specify the current status of the alert",
        required=False,
        value_list=list(DEFENDER_UPDATE_ALERT_STATUS_DICT.keys()),
    )
    assign_to: str = Param(
        description="Owner of the alert",
        required=False,
        cef_types=["email"],
    )
    classification: str = Param(
        description="Specification of the alert",
        required=False,
        value_list=list(DEFENDER_UPDATE_ALERT_CLASSIFICATION_DICT.keys()),
    )
    determination: str = Param(
        description="Specifies the determination of the alert",
        required=False,
        value_list=list(DEFENDER_UPDATE_ALERT_DETERMINATION_DICT.keys()),
    )


class UpdateAlertOutput(PermissiveActionOutput):
    assignedTo: str | None = OutputField(cef_types=["email"])
    category: str | None = OutputField()
    classification: str | None = OutputField()
    createdDateTime: str | None = OutputField()
    description: str | None = OutputField()
    detectionSource: str | None = OutputField()
    determination: str | None = OutputField()
    id: str | None = OutputField(cef_types=["defender alert id"])
    incidentId: str | None = OutputField(cef_types=["defender incident id"])
    incidentWebUrl: str | None = OutputField(cef_types=["url"])
    lastUpdateDateTime: str | None = OutputField()
    providerAlertId: str | None = OutputField(cef_types=["defender alert id"])
    serviceSource: str | None = OutputField()
    severity: str | None = OutputField(cef_types=["defender severity"])
    status: str | None = OutputField()
    tenantId: str | None = OutputField()
    title: str | None = OutputField()


@app.view_handler(template="microsoft365defender_update_alert.html")
def render_update_alert(outputs: list[UpdateAlertOutput]) -> dict:
    data = [o.model_dump() for o in outputs]
    return {"results": [{"data": data, "param": {}, "summary": {}}]}


@app.action(
    description="Update the properties of an alert object",
    action_type="generic",
    read_only=False,
    view_handler=render_update_alert,
)
def update_alert(
    params: UpdateAlertParams, soar: SOARClient, asset: Asset
) -> list[UpdateAlertOutput]:
    client = get_client(asset)

    if not any(
        (params.status, params.assign_to, params.classification, params.determination)
    ):
        raise ActionFailure(DEFENDER_NO_PARAMETER_PROVIDED)

    endpoint = DEFENDER_ALERTS_ID_ENDPOINT.format(input=params.alert_id)
    current = client.make_rest_call(endpoint)

    request_body = {}

    status = params.status or current.get(DEFENDER_JSON_STATUS)
    if status:
        if params.status:
            if params.status not in DEFENDER_UPDATE_ALERT_STATUS_DICT:
                raise ActionFailure(DEFENDER_INVALID_STATUS)
            request_body[DEFENDER_JSON_STATUS] = DEFENDER_UPDATE_ALERT_STATUS_DICT[
                params.status
            ]
        else:
            request_body[DEFENDER_JSON_STATUS] = status

    assigned_to = params.assign_to or current.get(DEFENDER_RESPONSE_ASSIGNED_TO)
    if assigned_to:
        request_body[DEFENDER_RESPONSE_ASSIGNED_TO] = assigned_to

    classification = params.classification or current.get(DEFENDER_JSON_CLASSIFICATION)
    if classification:
        if params.classification:
            if params.classification not in DEFENDER_UPDATE_ALERT_CLASSIFICATION_DICT:
                raise ActionFailure(DEFENDER_INVALID_CLASSIFICATION)
            request_body[DEFENDER_JSON_CLASSIFICATION] = (
                DEFENDER_UPDATE_ALERT_CLASSIFICATION_DICT[params.classification]
            )
        else:
            request_body[DEFENDER_JSON_CLASSIFICATION] = classification

    determination = params.determination or current.get(DEFENDER_JSON_DETERMINATION)
    if determination:
        if params.determination:
            if params.determination not in DEFENDER_UPDATE_ALERT_DETERMINATION_DICT:
                raise ActionFailure(DEFENDER_INVALID_DETERMINATION)
            request_body[DEFENDER_JSON_DETERMINATION] = (
                DEFENDER_UPDATE_ALERT_DETERMINATION_DICT[params.determination]
            )
        else:
            request_body[DEFENDER_JSON_DETERMINATION] = determination

    response = client.make_rest_call(
        endpoint, data=json.dumps(request_body), method="patch"
    )

    soar.set_message(DEFENDER_ALERT_UPDATED_SUCCESSFULLY)
    return [UpdateAlertOutput(**fix_up_odata_fields(response))]
