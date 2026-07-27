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

from collections.abc import Iterator
from copy import deepcopy
from datetime import datetime, timedelta, UTC

from soar_sdk.abstract import SOARClient
from soar_sdk.app import App
from soar_sdk.asset import AssetField, BaseAsset, FieldCategory
from soar_sdk.auth import AuthorizationCodeFlow
from soar_sdk.logging import getLogger
from soar_sdk.models.artifact import Artifact
from soar_sdk.models.container import Container
from soar_sdk.params import OnPollParams
from soar_sdk.webhooks.models import WebhookRequest, WebhookResponse

from .consts import (
    DEFENDER_APP_DT_STR_FORMAT,
    DEFENDER_AUTHORIZE_URL,
    DEFENDER_CBA_FIELDS_ERROR,
    DEFENDER_CBA_INTERACTIVE_ERROR,
    DEFENDER_FIELD_CONFLICT_ERROR,
    DEFENDER_INCIDENT_DEFAULT_LIMIT_FOR_SCHEDULE_POLLING,
    DEFENDER_JSON_LAST_MODIFIED,
    DEFENDER_LIST_INCIDENTS_ENDPOINT,
    DEFENDER_LOGIN_BASE_URL,
    DEFENDER_MAX_TIE_IDS,
    DEFENDER_RESOURCE_URL,
    DEFENDER_TEST_CONNECTIVITY_PASSED_MSG,
    LOG_CONFIG_TIME_POLL_NOW,
    LOG_GREATER_EQUAL_TIME_ERROR,
    LOG_UTC_SINCE_TIME_ERROR,
    STATE_FIRST_RUN,
    STATE_LAST_IDS,
    STATE_LAST_TIME,
)
from .helper import (
    Microsoft365DefenderClient,
    fix_up_odata_fields,
    migrate_legacy_ingest_state,
    validate_integer,
)

logger = getLogger()


class Asset(BaseAsset):
    tenant_id: str = AssetField(
        description="Tenant ID", category=FieldCategory.CONNECTIVITY
    )
    client_id: str = AssetField(
        description="Client ID", category=FieldCategory.CONNECTIVITY
    )
    client_secret: str | None = AssetField(
        description="Client Secret", sensitive=True, category=FieldCategory.CONNECTIVITY
    )
    certificate_thumbprint: str | None = AssetField(
        description="Certificate Thumbprint (required for CBA)",
        sensitive=True,
        category=FieldCategory.CONNECTIVITY,
    )
    certificate_private_key: str | None = AssetField(
        description="Certificate Private Key (.PEM)",
        sensitive=True,
        category=FieldCategory.CONNECTIVITY,
    )
    timeout: float | None = AssetField(
        description="HTTP API timeout in seconds",
        default=30,
        category=FieldCategory.CONNECTIVITY,
    )
    non_interactive: bool | None = AssetField(
        description="Non-Interactive Auth",
        default=False,
        category=FieldCategory.CONNECTIVITY,
    )
    max_incidents_per_poll: float | None = AssetField(
        description="Maximum Incidents for scheduled/interval polling for each cycle",
        default=1000,
        category=FieldCategory.INGEST,
    )
    start_time: str | None = AssetField(
        description="Start time for schedule/interval/manual poll (Use this format: 1970-01-01T00:00:00Z)",
        category=FieldCategory.INGEST,
    )
    filter: str | None = AssetField(
        description="Filter incidents based on property (example: status ne 'active')",
        category=FieldCategory.INGEST,
    )

    def validate_auth(self) -> None:
        """Enforce the same auth-mode constraints as the original connector."""
        if self.client_secret is None:
            if (
                self.certificate_thumbprint is None
                or self.certificate_private_key is None
            ):
                raise ValueError(DEFENDER_CBA_FIELDS_ERROR)
            if not self.non_interactive:
                raise ValueError(DEFENDER_CBA_INTERACTIVE_ERROR)
        elif (
            self.certificate_thumbprint is not None
            or self.certificate_private_key is not None
        ):
            raise ValueError(DEFENDER_FIELD_CONFLICT_ERROR)


def get_client(asset: Asset) -> Microsoft365DefenderClient:
    asset.validate_auth()
    return Microsoft365DefenderClient(asset)


app = App(
    name="Microsoft 365 Defender",
    app_type="endpoint",
    logo="logo_microsoft365defender.svg",
    logo_dark="logo_microsoft365defender_dark.svg",
    product_vendor="Microsoft",
    product_name="Microsoft 365 Defender",
    publisher="Splunk",
    appid="69a23453-0649-4f5b-8abd-c2b64b53ab5b",
    fips_compliant=True,
    asset_cls=Asset,
).enable_webhooks(default_requires_auth=False)


def _authorization_flow(asset: Asset, soar: SOARClient) -> AuthorizationCodeFlow:
    tenant = asset.tenant_id
    return AuthorizationCodeFlow(
        asset.auth_state,
        soar.get_asset_id(),
        client_id=asset.client_id,
        client_secret=asset.client_secret,
        authorization_endpoint=f"{DEFENDER_LOGIN_BASE_URL}{DEFENDER_AUTHORIZE_URL.format(tenant_id=tenant)}",
        token_endpoint=f"{DEFENDER_LOGIN_BASE_URL}/{tenant}/oauth2/token",
        redirect_uri=app.get_webhook_url("oauth_callback"),
        use_pkce=False,
        extra_auth_params={"resource": DEFENDER_RESOURCE_URL},
        extra_token_params={"resource": DEFENDER_RESOURCE_URL},
    )


@app.test_connectivity()
def test_connectivity(soar: SOARClient, asset: Asset) -> None:
    asset.validate_auth()
    client = Microsoft365DefenderClient(asset)

    if not asset.non_interactive:
        flow = _authorization_flow(asset, soar)
        auth_url = flow.get_authorization_url()
        logger.progress(
            f"Please authorize user in a separate tab using URL: {auth_url}"
        )
        flow.wait_for_authorization(
            on_progress=lambda i: logger.info(f"Waiting for authorization... ({i})")
        )
    else:
        logger.progress("Generating access token")
        client.fetch_token()

    logger.progress("Getting info about alerts")
    client.make_rest_call("/security/alerts_v2", params={"$top": 1})
    soar.set_message(DEFENDER_TEST_CONNECTIVITY_PASSED_MSG)
    logger.info(DEFENDER_TEST_CONNECTIVITY_PASSED_MSG)


@app.webhook("oauth_callback")
def oauth_callback(request: WebhookRequest[Asset]) -> WebhookResponse:
    query_params = {k: v[0] if v else "" for k, v in request.query.items()}

    if "error" in query_params:
        reason = query_params.get("error_description", "Unknown error")
        return WebhookResponse.text_response(
            content=f"Authorization failed: {reason}", status_code=400
        )

    code = query_params.get("code")
    if not code:
        return WebhookResponse.text_response(
            content="Missing authorization code", status_code=400
        )

    asset = request.asset
    flow = AuthorizationCodeFlow(
        asset.auth_state,
        query_params.get("state", ""),
        client_id=asset.client_id,
        client_secret=asset.client_secret,
        authorization_endpoint=f"{DEFENDER_LOGIN_BASE_URL}{DEFENDER_AUTHORIZE_URL.format(tenant_id=asset.tenant_id)}",
        token_endpoint=f"{DEFENDER_LOGIN_BASE_URL}/{asset.tenant_id}/oauth2/token",
        redirect_uri=app.get_webhook_url("oauth_callback"),
        use_pkce=False,
    )
    flow.set_authorization_code(code)

    return WebhookResponse.text_response(
        content="Code received. Please close this window, the action will continue to get new token.",
        status_code=200,
    )


def _check_date_format(date: str) -> None:
    try:
        parsed = datetime.strptime(date, DEFENDER_APP_DT_STR_FORMAT).replace(tzinfo=UTC)
    except Exception as e:
        raise ValueError(
            f"Invalid date string received. Error occurred while checking date format. Error: {e}"
        ) from e

    epoch = datetime.strptime(
        "1970-01-01T00:00:00Z", DEFENDER_APP_DT_STR_FORMAT
    ).replace(tzinfo=UTC)
    if parsed < epoch:
        raise ValueError(LOG_UTC_SINCE_TIME_ERROR)
    if parsed >= datetime.now(UTC):
        raise ValueError(LOG_GREATER_EQUAL_TIME_ERROR.format(LOG_CONFIG_TIME_POLL_NOW))


@app.on_poll()
def on_poll(
    params: OnPollParams, soar: SOARClient, asset: Asset
) -> Iterator[Container | Artifact]:
    client = get_client(asset)
    is_poll_now = params.is_manual_poll()

    poll_filter = asset.filter or ""
    orderby = "lastUpdateDateTime"
    last_modified_time = (datetime.now(UTC) - timedelta(days=7)).strftime(
        DEFENDER_APP_DT_STR_FORMAT
    )
    last_ids: list[str] = []

    if asset.start_time:
        _check_date_format(asset.start_time)
        last_modified_time = asset.start_time

    if is_poll_now:
        max_incidents = params.container_count
    else:
        max_incidents = validate_integer(
            asset.max_incidents_per_poll
            or DEFENDER_INCIDENT_DEFAULT_LIMIT_FOR_SCHEDULE_POLLING,
            "max_incidents",
        )
        migrate_legacy_ingest_state(asset)
        if asset.ingest_state.get(STATE_FIRST_RUN, True):
            asset.ingest_state[STATE_FIRST_RUN] = False
        elif last_time := asset.ingest_state.get(STATE_LAST_TIME):
            last_modified_time = last_time
            last_ids = asset.ingest_state.get(STATE_LAST_IDS, [])

    start_time_filter = f"lastUpdateDateTime ge {last_modified_time}"
    poll_filter += start_time_filter if not poll_filter else f" and {start_time_filter}"

    # lastUpdateDateTime ge is inclusive, so incidents already ingested at the previous
    # checkpoint are fetched again. Over-fetch by the size of that tie group and drop
    # the already-seen ids, so a run of same-second updates can't stall the checkpoint.
    endpoint = f"{DEFENDER_LIST_INCIDENTS_ENDPOINT}?$expand=alerts"
    incident_list = client.paginator(
        endpoint, max_incidents + len(last_ids), 0, poll_filter, orderby
    )
    if last_ids:
        incident_list = [
            incident
            for incident in incident_list
            if not (
                incident.get("id") in last_ids
                and incident.get(DEFENDER_JSON_LAST_MODIFIED) == last_modified_time
            )
        ]
    incident_list = incident_list[:max_incidents]
    logger.progress(f"Successfully fetched {len(incident_list)} incidents.")

    for incident in incident_list:
        alerts = incident.pop("alerts", [])
        container_id = incident["id"]

        yield Container(
            name=incident.get("displayName", "incident Artifact"),
            description="incident ingested using MS Defender API",
            source_data_identifier=container_id,
        )
        for alert in alerts:
            yield Artifact(
                label="alert",
                name=alert.get("title"),
                source_data_identifier=alert.get("id"),
                data=alert,
                cef=fix_up_odata_fields(deepcopy(alert)),
            )
        yield Artifact(
            label="incident",
            name="incident Artifact",
            source_data_identifier=incident.get("id"),
            data=incident,
            cef=fix_up_odata_fields(deepcopy(incident)),
        )

    if not is_poll_now and incident_list:
        last = incident_list[-1].get(DEFENDER_JSON_LAST_MODIFIED)
        if last:
            new_tied_ids = [
                incident.get("id")
                for incident in incident_list
                if incident.get(DEFENDER_JSON_LAST_MODIFIED) == last
            ]
            # Still inside the same tie group as last poll: accumulate, don't forget
            # ids seen in an earlier poll at this exact boundary.
            tied_ids = (
                last_ids + new_tied_ids if last == last_modified_time else new_tied_ids
            )
            asset.ingest_state[STATE_LAST_TIME] = last
            asset.ingest_state[STATE_LAST_IDS] = tied_ids[-DEFENDER_MAX_TIE_IDS:]


# Actions self-register via @app.action() on import.
from .actions import (  # noqa: F401
    get_alert,
    get_incident,
    list_alerts,
    list_incidents,
    make_request,
    run_query,
    update_alert,
    update_incident,
)
