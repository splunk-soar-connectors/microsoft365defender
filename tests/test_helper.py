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
import pytest

from src.helper import (
    Microsoft365DefenderClient,
    encode_graph_path_segment,
    validate_graph_pagination_url,
)


@pytest.mark.parametrize(
    ("value", "encoded"),
    [
        ("123", "123"),
        ("../alerts", "..%2Falerts"),
        ("alert?expand=evidence", "alert%3Fexpand%3Devidence"),
    ],
)
def test_encode_graph_path_segment(value, encoded):
    assert encode_graph_path_segment(value) == encoded


@pytest.mark.parametrize("value", [".", ".."])
def test_encode_graph_path_segment_rejects_dot_segments(value):
    with pytest.raises(ValueError, match="cannot be dot path segments"):
        encode_graph_path_segment(value)


@pytest.mark.parametrize(
    "url",
    [
        "https://graph.microsoft.com/v1.0/security/incidents?$skiptoken=next",
        "https://graph.microsoft.com/v1.0/security/alerts_v2?$skiptoken=next",
    ],
)
def test_validate_graph_pagination_url_accepts_graph_origin(url):
    validate_graph_pagination_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com/v1.0/security/incidents",
        "http://graph.microsoft.com/v1.0/security/incidents",
        "https://graph.microsoft.com:444/v1.0/security/incidents",
        "https://graph.microsoft.com:invalid/v1.0/security/incidents",
    ],
)
def test_validate_graph_pagination_url_rejects_other_origins(url):
    with pytest.raises(ValueError, match="outside Microsoft Graph"):
        validate_graph_pagination_url(url)


def test_paginator_rejects_empty_continuation_page(mocker):
    client = object.__new__(Microsoft365DefenderClient)
    client.make_rest_call = mocker.Mock(
        return_value={
            "value": [],
            "@odata.nextLink": "https://graph.microsoft.com/v1.0/next",
        }
    )

    with pytest.raises(ValueError, match="made no progress"):
        client.paginator("/v1.0/security/incidents", 10)


def test_paginator_rejects_repeated_continuation_url(mocker):
    page_url = "https://graph.microsoft.com/v1.0/next"
    client = object.__new__(Microsoft365DefenderClient)
    client.make_rest_call = mocker.Mock(
        side_effect=[
            {"value": [{"id": "one"}], "@odata.nextLink": page_url},
            {"value": [{"id": "two"}], "@odata.nextLink": page_url},
        ]
    )

    with pytest.raises(ValueError, match="repeated a page URL"):
        client.paginator("/v1.0/security/incidents", 10)


def test_paginator_enforces_page_limit(mocker, monkeypatch):
    client = object.__new__(Microsoft365DefenderClient)
    client.make_rest_call = mocker.Mock(
        side_effect=[
            {
                "value": [{"id": str(page)}],
                "@odata.nextLink": f"https://graph.microsoft.com/v1.0/next/{page}",
            }
            for page in range(3)
        ]
    )
    monkeypatch.setattr("src.helper.MAX_GRAPH_PAGES", 2)

    with pytest.raises(ValueError, match="exceeded the page limit"):
        client.paginator("/v1.0/security/incidents", 10)
