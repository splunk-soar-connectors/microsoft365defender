import pytest

from src.helper import validate_graph_pagination_url


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
