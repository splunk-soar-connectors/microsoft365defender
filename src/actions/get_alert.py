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
    DEFENDER_ALERTS_ID_ENDPOINT,
    DEFENDER_SUCCESSFULLY_RETRIEVED_ALERT,
)
from ..helper import fix_up_odata_fields
from .list_alerts import render_display_alerts


class GetAlertParams(Params):
    alert_id: str = Param(
        description="ID of the alert",
        required=True,
        primary=True,
        cef_types=["defender alert id"],
    )


class GetAlertOutput(PermissiveActionOutput):
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


@app.action(
    description="Retrieve the properties and relationships of an alert object",
    action_type="investigate",
    read_only=True,
    view_handler=render_display_alerts,
)
def get_alert(
    params: GetAlertParams, soar: SOARClient, asset: Asset
) -> list[GetAlertOutput]:
    client = get_client(asset)

    endpoint = DEFENDER_ALERTS_ID_ENDPOINT.format(input=params.alert_id)
    response = client.make_rest_call(endpoint)

    soar.set_message(DEFENDER_SUCCESSFULLY_RETRIEVED_ALERT)
    return [GetAlertOutput(**fix_up_odata_fields(response))]
