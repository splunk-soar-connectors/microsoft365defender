# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import OutputField, PermissiveActionOutput
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import Param, Params

from ..app import Asset, app, get_client
from ..consts import (
    DEFENDER_COMMENT_ADDED_SUCCESSFULLY,
    DEFENDER_COMMENT_ALERT_ID_ENDPOINT,
    DEFENDER_UNEXPECTED_RESPONSE_ERROR,
)
from ..helper import encode_graph_path_segment, fix_up_odata_fields


class CreateCommentParams(Params):
    alert_id: str = Param(
        description="ID of the alert",
        required=True,
        primary=True,
        cef_types=["defender alert id"],
    )
    comment: str = Param(
        description="The comment to be added to the alert",
        required=True,
    )


class AlertCommentOutput(PermissiveActionOutput):
    comment: str | None = OutputField()
    createdByDisplayName: str | None = OutputField()
    createdDateTime: str | None = OutputField()


class CreateCommentOutput(PermissiveActionOutput):
    value: list[AlertCommentOutput] = OutputField()
    odata_context: str | None = OutputField()


@app.action(
    description="Create a comment for an alert",
    verbose=(
        "The response contains all comments on the alert, including the new comment."
    ),
    action_type="generic",
    read_only=False,
    render_as="table",
)
def create_comment(
    params: CreateCommentParams, soar: SOARClient, asset: Asset
) -> list[CreateCommentOutput]:
    if not params.alert_id or not params.alert_id.strip():
        raise ActionFailure("Please provide a non-empty alert ID")
    if not params.comment or not params.comment.strip():
        raise ActionFailure("Please provide a non-empty comment")

    endpoint = DEFENDER_COMMENT_ALERT_ID_ENDPOINT.format(
        input=encode_graph_path_segment(params.alert_id)
    )
    client = get_client(asset)
    response = client.make_rest_call(
        endpoint,
        data=json.dumps(
            {
                "@odata.type": "microsoft.graph.security.alertComment",
                "comment": params.comment,
            }
        ),
        method="post",
    )

    comments = response.get("value") if isinstance(response, dict) else None
    if not isinstance(comments, list) or not all(
        isinstance(comment, dict) for comment in comments
    ):
        raise ActionFailure(DEFENDER_UNEXPECTED_RESPONSE_ERROR)

    soar.set_message(DEFENDER_COMMENT_ADDED_SUCCESSFULLY)
    return [CreateCommentOutput(**fix_up_odata_fields(response))]
