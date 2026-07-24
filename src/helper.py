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

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Any

import requests
from soar_sdk.auth import (
    CertificateCredentials,
    CertificateOAuthClient,
    ClientCredentialsFlow,
    OAuthConfig,
    SOARAssetOAuthClient,
)
from soar_sdk.auth.client import AuthorizationRequiredError, TokenExpiredError
from soar_sdk.auth.models import OAuthGrantType
from soar_sdk.logging import getLogger

from .consts import (
    DEFENDER_CBA_KEY_ERROR,
    DEFENDER_LOGIN_BASE_URL,
    DEFENDER_MSGRAPH_API_BASE_URL,
    DEFENDER_NEXT_PAGE_TOKEN,
    DEFENDER_NON_NEG_INT_MSG,
    DEFENDER_NON_NEG_NON_ZERO_INT_MSG,
    DEFENDER_RESOURCE_URL,
    DEFENDER_SERVER_TOKEN_URL,
    DEFENDER_TOKEN_NOT_AVAILABLE_MSG,
    DEFENDER_UNEXPECTED_RESPONSE_ERROR,
    DEFENDER_VALID_INTEGER_MSG,
    STATE_FIRST_RUN,
    STATE_LAST_TIME,
)

if TYPE_CHECKING:
    from .app import Asset

logger = getLogger()


class Microsoft365DefenderClient:
    """Microsoft Graph client for M365 Defender supporting three auth modes.

    Auth mode is derived from the asset config, matching the original connector:

    - interactive (authorization code): client_secret set, non_interactive False.
      Tokens (and refresh token) are obtained during test connectivity via the
      webhook callback and reused/refreshed here.
    - non-interactive (client credentials): client_secret set, non_interactive True.
    - certificate based (CBA): certificate_thumbprint + private key set,
      non_interactive True.

    Tokens are persisted in ``asset.auth_state`` by the SDK OAuth client under the
    ``oauth`` key. Microsoft's v1 token endpoint uses ``resource`` instead of
    ``scope``, so the Graph resource is passed as an extra parameter.
    """

    def __init__(self, asset: Asset) -> None:
        self.asset = asset
        self._tenant = asset.tenant_id
        self._client_id = asset.client_id
        self._client_secret = asset.client_secret
        self._non_interactive = bool(asset.non_interactive)
        self._thumbprint = asset.certificate_thumbprint
        self._certificate_private_key = asset.certificate_private_key
        self._cba_auth = self._client_secret is None
        self._timeout = int(asset.timeout) if asset.timeout else 30

    @property
    def token_endpoint(self) -> str:
        return f"{DEFENDER_LOGIN_BASE_URL}{DEFENDER_SERVER_TOKEN_URL.format(tenant_id=self._tenant)}"

    def _oauth_config(self, grant_type: OAuthGrantType) -> OAuthConfig:
        return OAuthConfig(
            client_id=self._client_id,
            client_secret=self._client_secret,
            token_endpoint=self.token_endpoint,
            grant_type=grant_type,
        )

    def _client_credentials_flow(self) -> ClientCredentialsFlow:
        return ClientCredentialsFlow(
            self.asset.auth_state,
            client_id=self._client_id,
            client_secret=self._client_secret,
            token_endpoint=self.token_endpoint,
            extra_params={"resource": DEFENDER_RESOURCE_URL},
        )

    def _certificate_client(self) -> CertificateOAuthClient:
        certificate = CertificateCredentials(
            certificate_thumbprint=self._thumbprint,
            private_key=self._get_private_key(),
            tenant_id=self._tenant,
        )
        return CertificateOAuthClient(
            self._oauth_config(OAuthGrantType.CLIENT_CREDENTIALS),
            self.asset.auth_state,
            certificate,
        )

    def _authorization_client(self) -> SOARAssetOAuthClient:
        return SOARAssetOAuthClient(
            self._oauth_config(OAuthGrantType.AUTHORIZATION_CODE),
            self.asset.auth_state,
        )

    def _get_private_key(self) -> str:
        """Rebuild the PEM private key that SOAR flattens newlines into spaces."""
        p = re.compile("(-----.*?-----) (.*) (-----.*?-----)")
        m = p.match(self._certificate_private_key or "")
        if not m:
            raise ValueError(DEFENDER_CBA_KEY_ERROR)
        return "\n".join([m.group(1), m.group(2).replace(" ", "\n"), m.group(3)])

    # ------------------------------------------------------------------ #
    # Token acquisition
    # ------------------------------------------------------------------ #
    def fetch_token(self) -> None:
        """Acquire a token for the non-interactive modes (used by test connectivity)."""
        if self._cba_auth:
            self._certificate_client().fetch_token_with_certificate(
                extra_params={"resource": DEFENDER_RESOURCE_URL}
            )
        else:
            self._client_credentials_flow().authenticate()

    def access_token(self) -> str:
        """Return a valid access token, acquiring or refreshing as needed."""
        if self._cba_auth:
            client = self._certificate_client()
            try:
                return client.get_valid_token(auto_refresh=False).access_token
            except (AuthorizationRequiredError, TokenExpiredError):
                token = client.fetch_token_with_certificate(
                    extra_params={"resource": DEFENDER_RESOURCE_URL}
                )
                return token.access_token

        if self._non_interactive:
            return self._client_credentials_flow().get_token().access_token

        # Interactive authorization-code mode: token must already exist from
        # test connectivity; refresh transparently when expired.
        client = self._authorization_client()
        try:
            return client.get_valid_token(auto_refresh=True).access_token
        except (AuthorizationRequiredError, TokenExpiredError) as e:
            raise ValueError(DEFENDER_TOKEN_NOT_AVAILABLE_MSG) from e

    # ------------------------------------------------------------------ #
    # REST calls
    # ------------------------------------------------------------------ #
    def make_rest_call(
        self,
        endpoint: str,
        params: dict | None = None,
        data: Any = None,
        method: str = "get",
        append: bool = True,
    ) -> dict:
        url = f"{DEFENDER_MSGRAPH_API_BASE_URL}{endpoint}" if append else endpoint
        headers = {
            "Authorization": f"Bearer {self.access_token()}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        response = self._request(url, headers, params, data, method)
        if response.status_code == 401:
            headers["Authorization"] = f"Bearer {self.access_token()}"
            response = self._request(url, headers, params, data, method)
        return self._process_response(response)

    def _request(
        self,
        url: str,
        headers: dict,
        params: dict | None,
        data: Any,
        method: str,
    ) -> requests.Response:
        try:
            request_func = getattr(requests, method)
        except AttributeError as e:
            raise ValueError(f"Invalid method: {method}") from e

        try:
            return request_func(
                url, data=data, headers=headers, params=params, timeout=self._timeout
            )
        except Exception as e:
            raise ConnectionError(f"Error connecting to server. Details: {e}") from e

    def _process_response(self, response: requests.Response) -> dict:
        content_type = response.headers.get("Content-Type", "")

        if "json" in content_type or "text/javascript" in content_type:
            try:
                resp_json = response.json()
            except Exception as e:
                raise ValueError(f"Unable to parse JSON response. Error: {e}") from e
            if 200 <= response.status_code < 399:
                return resp_json
            raise ValueError(self._json_error(response, resp_json))

        if not response.text:
            if response.status_code in (200, 204):
                return {}
            raise ValueError(
                f"Status Code: {response.status_code}. Error: Empty response and no information in the header"
            )

        error_message = response.text.replace("{", "{{").replace("}", "}}")
        raise ValueError(
            f"Can't process response from server. Status Code: {response.status_code} Data from server: {error_message}"
        )

    @staticmethod
    def _json_error(response: requests.Response, resp_json: dict) -> str:
        error = resp_json.get("error")
        if isinstance(error, dict) and error.get("code"):
            return "Error from server. Status Code: {} Error Code: {} Data from server: {}".format(
                response.status_code, error.get("code"), error.get("message")
            )
        if not isinstance(error, dict) and resp_json.get("error_description"):
            err = "Error:{}, Error Description:{}".format(
                error, resp_json.get("error_description")
            )
            return f"Error from server. Status Code: {response.status_code} Data from server: {err}"
        text = response.text.replace("{", "{{").replace("}", "}}")
        return f"Error from server. Status Code: {response.status_code} Data from server: {text}"

    # ------------------------------------------------------------------ #
    # Pagination
    # ------------------------------------------------------------------ #
    def paginator(
        self,
        endpoint: str,
        limit: int,
        offset: int = 0,
        odata_filter: str | None = None,
        orderby: str | None = None,
    ) -> list:
        resource_list: list = []
        next_page_token = ""

        while True:
            params: dict = {}
            if not next_page_token and odata_filter:
                params["$filter"] = odata_filter
            if not next_page_token and orderby:
                params["$orderby"] = orderby
            if not next_page_token and offset:
                params["$skip"] = offset
            if next_page_token:
                endpoint = next_page_token

            response = self.make_rest_call(
                endpoint, params=params, append=not next_page_token
            )

            if not response:
                raise ValueError(DEFENDER_UNEXPECTED_RESPONSE_ERROR)

            resource_list.extend(response.get("value", []))

            next_page_token = response.get(DEFENDER_NEXT_PAGE_TOKEN)
            if not next_page_token or len(resource_list) >= limit:
                break

        return resource_list[:limit]


def validate_integer(value: Any, key: str, allow_zero: bool = True) -> int | None:
    if value is None:
        return None
    try:
        if not float(value).is_integer():
            raise ValueError(DEFENDER_VALID_INTEGER_MSG.format(key))
        value = int(value)
    except (TypeError, ValueError) as e:
        raise ValueError(DEFENDER_VALID_INTEGER_MSG.format(key)) from e

    if value < 0:
        raise ValueError(DEFENDER_NON_NEG_INT_MSG.format(key))
    if not allow_zero and value == 0:
        raise ValueError(DEFENDER_NON_NEG_NON_ZERO_INT_MSG.format(key))
    return value


def migrate_legacy_ingest_state(asset: Asset) -> None:
    """Seed SDK ingest state from the pre-SDK connector's flat checkpoint keys.

    The legacy BaseConnector app stored `first_run` and `last_time` as top-level keys in the
    asset state file. The SDK keeps ingestion checkpoints in a separate encrypted partition, so
    upgrading in place would otherwise reset the checkpoint and re-ingest incidents from the
    fallback window. This only migrates until the SDK partition has its own checkpoint.
    """
    if STATE_LAST_TIME in asset.ingest_state:
        return

    legacy_state = asset.ingest_state.backend.load_state() or {}

    if (legacy_last_time := legacy_state.get(STATE_LAST_TIME)) is not None:
        asset.ingest_state[STATE_LAST_TIME] = legacy_last_time
        asset.ingest_state[STATE_FIRST_RUN] = False


def fix_up_odata_fields(response: dict) -> dict:
    """Create datapath-friendly aliases for odata fields containing periods."""
    if not isinstance(response, dict):
        return response

    if "@odata.context" in response:
        response["odata_context"] = response["@odata.context"]

    evidence = response.get("evidence", [])
    if isinstance(evidence, list):
        for evidence_item in evidence:
            if isinstance(evidence_item, dict) and "@odata.type" in evidence_item:
                evidence_item["odata_type"] = evidence_item["@odata.type"]

    additional_data = response.get("additionalData", {})
    if (
        isinstance(additional_data, dict)
        and additional_data.get("Intent@odata.type") is not None
    ):
        response["Intent_odata_type"] = additional_data.get("Intent@odata.type")

    return response


def serialize_complex_fields(resp: dict, fields: list[str]) -> dict:
    """Serialize complex fields (dict/list) to JSON strings for ActionOutput."""
    for field in fields:
        if field in resp and isinstance(resp[field], dict | list):
            resp[field] = json.dumps(resp[field])
    return resp
