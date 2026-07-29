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

DEFENDER_APP_DT_STR_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

DEFENDER_LOGIN_BASE_URL = "https://login.microsoftonline.com"
DEFENDER_RESOURCE_URL = "https://graph.microsoft.com"
DEFENDER_MSGRAPH_API_BASE_URL = "https://graph.microsoft.com/v1.0"
DEFENDER_SERVER_TOKEN_URL = "/{tenant_id}/oauth2/token"  # noqa: S105
DEFENDER_AUTHORIZE_URL = "/{tenant_id}/oauth2/authorize"

DEFENDER_ALERTS_ENDPOINT = "/security/alerts_v2"
DEFENDER_RUN_QUERY_ENDPOINT = "/security/runHuntingQuery"
DEFENDER_LIST_INCIDENTS_ENDPOINT = "/security/incidents"
DEFENDER_INCIDENT_ID_ENDPOINT = "/security/incidents/{input}"
DEFENDER_ALERTS_ID_ENDPOINT = "/security/alerts_v2/{input}"

DEFAULT_TIMEOUT = 30
DEFENDER_INCIDENT_DEFAULT_LIMIT = 50
DEFENDER_ALERT_DEFAULT_LIMIT = 2000
DEFENDER_INCIDENT_DEFAULT_LIMIT_FOR_SCHEDULE_POLLING = 1000
DEFENDER_INCIDENT_DEFAULT_OFFSET = 0
DEFENDER_NEXT_PAGE_TOKEN = "@odata.nextLink"  # noqa: S105

DEFENDER_CBA_FIELDS_ERROR = "Client Secret was not specified, in which case Certificate Thumbprint and Certificate Private Key are required"
DEFENDER_FIELD_CONFLICT_ERROR = (
    "Client Secret was specified as well as Certificate Thumbprint or Certificate Private Key. "
    "If Client Secret has a value, Certificate Thumbprint and Certificate Private Key values must be removed"
    "Alternatively, if Certificate Thumbprint and Certificate Private Key have values"
    ", Client Secret value must be removed"
)
DEFENDER_CBA_INTERACTIVE_ERROR = (
    "Certificate Based Authorization requires Non-Interactive Auth to be checked"
)
DEFENDER_CBA_KEY_ERROR = (
    "Error occurred while parsing the private key, is it in .PEM format?"
)

DEFENDER_TEST_CONNECTIVITY_PASSED_MSG = "Test connectivity passed"
DEFENDER_AUTHORIZE_USER_MSG = "Please authorize user in a separate tab using URL"
DEFENDER_GENERATING_ACCESS_TOKEN_MSG = "Generating access token"  # noqa: S105
DEFENDER_MAKING_CONNECTION_MSG = "Making Connection..."
DEFENDER_TOKEN_NOT_AVAILABLE_MSG = (
    "Token not available. Please run test connectivity first"  # noqa: S105
)
DEFENDER_UNEXPECTED_RESPONSE_ERROR = "Unexpected response retrieved"

DEFENDER_VALID_INTEGER_MSG = "Please provide a valid integer value in the {} parameter"
DEFENDER_NON_NEG_NON_ZERO_INT_MSG = (
    "Please provide a valid non-zero positive integer value in the {} parameter"
)
DEFENDER_NON_NEG_INT_MSG = (
    "Please provide a valid non-negative integer value in the {} parameter"
)

DEFENDER_LIMIT_KEY = "'limit' action parameter"
DEFENDER_OFFSET_KEY = "'offset' action parameter"
DEFENDER_TIMEOUT_KEY = "'timeout' asset parameter"

DEFENDER_INCIDENT_LIMIT = "limit"
DEFENDER_INCIDENT_OFFSET = "offset"
DEFENDER_INCIDENT_FILTER = "filter"
DEFENDER_INCIDENT_ORDER_BY = "orderby"
DEFENDER_INCIDENT_ID = "incident_id"
DEFENDER_ALERT_ID = "alert_id"
DEFENDER_JSON_QUERY = "query"
DEFENDER_JSON_STATUS = "status"
DEFENDER_JSON_ASSIGNED_TO = "assign_to"
DEFENDER_RESPONSE_ASSIGNED_TO = "assignedTo"
DEFENDER_JSON_CLASSIFICATION = "classification"
DEFENDER_JSON_DETERMINATION = "determination"

DEFENDER_INVALID_CLASSIFICATION = (
    "Please provide a valid value in the 'classification' parameter"
)
DEFENDER_INVALID_DETERMINATION = (
    "Please provide a valid value in the 'determination' parameter"
)
DEFENDER_INVALID_STATUS = "Please provide a valid value in the 'status' parameter"
DEFENDER_SUCCESSFULLY_RETRIEVED_INCIDENT = "Successfully retrieved the incident"
DEFENDER_SUCCESSFULLY_RETRIEVED_ALERT = "Successfully retrieved the alert"
DEFENDER_ALERT_UPDATED_SUCCESSFULLY = "Successfully updated the alert"
DEFENDER_INCIDENT_UPDATED_SUCCESSFULLY = "Successfully updated the incident"
DEFENDER_INCIDENT_NO_PARAMETER_PROVIDED = (
    "Please provide at least one of the properties to update the incident"
)
DEFENDER_NO_PARAMETER_PROVIDED = (
    "Please provide at least one of the properties to update the alert"
)

DEFENDER_UPDATE_ALERT_USER_PARAM_LIST = [
    DEFENDER_JSON_STATUS,
    DEFENDER_JSON_ASSIGNED_TO,
    DEFENDER_JSON_CLASSIFICATION,
    DEFENDER_JSON_DETERMINATION,
]

DEFENDER_UPDATE_ALERT_STATUS_DICT = {
    "New": "new",
    "In progress": "inProgress",
    "Resolved": "resolved",
}

DEFENDER_UPDATE_ALERT_CLASSIFICATION_DICT = {
    "Informational, expected activity": "informationalExpectedActivity",
    "False positive": "falsePositive",
    "True positive": "truePositive",
}

DEFENDER_UPDATE_ALERT_DETERMINATION_DICT = {
    "Malware": "malware",
    "Security testing": "securityTesting",
    "Unwanted software": "unwantedSoftware",
    "Multi staged attack": "multiStagedAttack",
    "Compromised account": "compromisedAccount",
    "Phishing": "phishing",
    "Malicious user activity": "maliciousUserActivity",
    "Not malicious": "notMalicious",
    "Not enough data to validate": "notEnoughDataToValidate",
    "Confirmed activity": "confirmedActivity",
    "Line of business application": "lineOfBusinessApplication",
    "Other": "other",
}

DEFENDER_UPDATE_INCIDENT_STATUS_DICT = {
    "Active": "active",
    "Resolved": "resolved",
    "Redirected": "redirected",
}

DEFENDER_UPDATE_INCIDENT_DETERMINATION_DICT = {
    "Unknown": "unknown",
    "apt": "apt",
    "Malware": "malware",
    "Security Personnel": "securityPersonnel",
    "Security testing": "securityTesting",
    "Unwanted software": "unwantedSoftware",
    "Other": "other",
    "Multi staged attack": "multiStagedAttack",
    "Phishing": "phishing",
    "Malicious user activity": "maliciousUserActivity",
    "Not malicious": "notMalicious",
    "Not enough data to validate": "notEnoughDataToValidate",
    "Line of business application": "lineOfBusinessApplication",
    "Unknown Future Value": "unknownFutureValue",
}

DEFENDER_UPDATE_INCIDENT_CLASSIFICATION_DICT = {
    "Informational, expected activity": "informationalExpectedActivity",
    "False Positive": "falsePositive",
    "True Positive": "truePositive",
    "Unknown": "unknown",
    "Unknown Future Value": "unknownFutureValue",
}

DEFENDER_INCIDENT_PARAMS_MAPPING = {
    "status": DEFENDER_UPDATE_INCIDENT_STATUS_DICT,
    "determination": DEFENDER_UPDATE_INCIDENT_DETERMINATION_DICT,
    "classification": DEFENDER_UPDATE_INCIDENT_CLASSIFICATION_DICT,
}

DEFENDER_INCIDENT_KEYS_MAPPING = {"assign_to": "assignedTo"}

DEFENDER_INVALID_INCIDENT_INPUT = "Please provide a valid value in the '{0}' parameter"

# For on_poll action
DEFENDER_CONFIG_FIRST_RUN_MAX_INCIDENTS = "max_incidents_per_poll"
STATE_FIRST_RUN = "first_run"
STATE_LAST_TIME = "last_time"
STATE_LAST_IDS = "last_ids"
DEFENDER_JSON_LAST_MODIFIED = "lastUpdateDateTime"
DEFENDER_MISSING_LAST_MODIFIED_ERROR = (
    "Last fetched incident is missing lastUpdateDateTime, cannot save poll checkpoint"
)
LOG_UTC_SINCE_TIME_ERROR = (
    "Please provide time in the span of UTC time since Unix epoch 1970-01-01T00:00:00Z."
)
LOG_GREATER_EQUAL_TIME_ERROR = (
    "Invalid {0}, can not be greater than or equal to current UTC time"
)
LOG_CONFIG_TIME_POLL_NOW = "'Time range for POLL NOW' or 'Start Time for Schedule/Manual POLL' asset configuration parameter"
