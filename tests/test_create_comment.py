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

import pytest
from soar_sdk.exceptions import ActionFailure

from src.actions.create_comment import CreateCommentParams, create_comment
from src.consts import DEFENDER_COMMENT_ADDED_SUCCESSFULLY


def test_create_comment_posts_to_encoded_alert_and_returns_comments(mocker):
    client = mocker.patch("src.actions.create_comment.get_client").return_value
    client.make_rest_call.return_value = {
        "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#comments",
        "value": [
            {
                "comment": "Earlier comment",
                "createdByDisplayName": "First analyst",
                "createdDateTime": "2026-01-01T00:00:00Z",
            },
            {
                "comment": "Investigation note",
                "createdByDisplayName": "Second analyst",
                "createdDateTime": "2026-01-02T00:00:00Z",
            },
        ],
    }
    soar = mocker.Mock()
    asset = mocker.sentinel.asset
    params = CreateCommentParams(
        alert_id="alert/1?source=defender", comment="Investigation note"
    )

    outputs = create_comment.__wrapped__(params, soar, asset)

    client.make_rest_call.assert_called_once()
    endpoint = client.make_rest_call.call_args.args[0]
    assert endpoint == "/security/alerts_v2/alert%2F1%3Fsource%3Ddefender/comments"
    assert client.make_rest_call.call_args.kwargs["method"] == "post"
    assert json.loads(client.make_rest_call.call_args.kwargs["data"]) == {
        "@odata.type": "microsoft.graph.security.alertComment",
        "comment": "Investigation note",
    }
    assert len(outputs) == 1
    assert outputs[0].model_dump() == {
        "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#comments",
        "odata_context": "https://graph.microsoft.com/v1.0/$metadata#comments",
        "value": [
            {
                "comment": "Earlier comment",
                "createdByDisplayName": "First analyst",
                "createdDateTime": "2026-01-01T00:00:00Z",
            },
            {
                "comment": "Investigation note",
                "createdByDisplayName": "Second analyst",
                "createdDateTime": "2026-01-02T00:00:00Z",
            },
        ],
    }
    soar.set_message.assert_called_once_with(DEFENDER_COMMENT_ADDED_SUCCESSFULLY)


@pytest.mark.parametrize(
    ("alert_id", "comment", "message"),
    [
        ("", "Investigation note", "non-empty alert ID"),
        ("  ", "Investigation note", "non-empty alert ID"),
        ("alert-1", "", "non-empty comment"),
        ("alert-1", "  ", "non-empty comment"),
    ],
)
def test_create_comment_rejects_blank_inputs(mocker, alert_id, comment, message):
    get_client = mocker.patch("src.actions.create_comment.get_client")
    params = CreateCommentParams(alert_id=alert_id, comment=comment)

    with pytest.raises(ActionFailure, match=message):
        create_comment.__wrapped__(params, mocker.Mock(), mocker.sentinel.asset)

    get_client.assert_not_called()


@pytest.mark.parametrize("response", [{}, {"value": "not a list"}, {"value": [None]}])
def test_create_comment_rejects_unexpected_response(mocker, response):
    client = mocker.patch("src.actions.create_comment.get_client").return_value
    client.make_rest_call.return_value = response
    soar = mocker.Mock()

    with pytest.raises(ActionFailure, match="Unexpected response"):
        create_comment.__wrapped__(
            CreateCommentParams(alert_id="alert-1", comment="Investigation note"),
            soar,
            mocker.sentinel.asset,
        )

    soar.set_message.assert_not_called()


def test_create_comment_propagates_graph_error(mocker):
    client = mocker.patch("src.actions.create_comment.get_client").return_value
    client.make_rest_call.side_effect = ValueError("Status Code: 403")
    soar = mocker.Mock()

    with pytest.raises(ValueError, match="403"):
        create_comment.__wrapped__(
            CreateCommentParams(alert_id="alert-1", comment="Investigation note"),
            soar,
            mocker.sentinel.asset,
        )

    soar.set_message.assert_not_called()
