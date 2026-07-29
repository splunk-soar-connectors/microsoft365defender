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
    DEFENDER_ALERT_DEFAULT_LIMIT,
    DEFENDER_ALERTS_ENDPOINT,
    DEFENDER_INCIDENT_DEFAULT_OFFSET,
    DEFENDER_LIMIT_KEY,
    DEFENDER_OFFSET_KEY,
)
from ..helper import fix_up_odata_fields, validate_integer


class ListAlertsParams(Params):
    limit: int = Param(
        description="Maximum number of alerts to return",
        required=False,
        default=DEFENDER_ALERT_DEFAULT_LIMIT,
    )
    offset: int = Param(
        description="Number of alerts to skip",
        required=False,
        default=DEFENDER_INCIDENT_DEFAULT_OFFSET,
    )
    filter: str = Param(
        description="Filter alerts based on property",
        required=False,
    )
    orderby: str = Param(
        description="Sort the alerts based on property",
        required=False,
    )


class ListAlertsOutput(PermissiveActionOutput):
    alertWebUrl: str | None = OutputField(cef_types=["url"])
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


class ListAlertsSummary(ActionOutput):
    total_alerts: int = OutputField(example_values=[10])


@app.view_handler(template="microsoft365defender_list_alerts.html")
def render_display_alerts(outputs: list[ListAlertsOutput]) -> dict:
    data = [o.model_dump() for o in outputs]
    return {
        "results": [{"data": data, "param": {}, "summary": {"total_alerts": len(data)}}]
    }


@app.action(
    description="Get the list of recent alerts",
    action_type="investigate",
    read_only=True,
    view_handler=render_display_alerts,
    summary_type=ListAlertsSummary,
)
def list_alerts(
    params: ListAlertsParams, soar: SOARClient, asset: Asset
) -> list[ListAlertsOutput]:
    client = get_client(asset)

    limit = validate_integer(params.limit, DEFENDER_LIMIT_KEY, allow_zero=False)
    offset = validate_integer(params.offset, DEFENDER_OFFSET_KEY)

    alert_list = client.paginator(
        DEFENDER_ALERTS_ENDPOINT, limit, offset, params.filter, params.orderby
    )

    outputs = [ListAlertsOutput(**fix_up_odata_fields(alert)) for alert in alert_list]

    soar.set_summary(ListAlertsSummary(total_alerts=len(outputs)))
    return outputs
