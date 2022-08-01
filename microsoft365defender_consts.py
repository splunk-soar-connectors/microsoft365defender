# File: microsoft365defender_consts.py
#
# Copyright (c) 2022 Splunk Inc.
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

# Define your constants here
DEFENDER_USER_AGENT = "M365dPartner-Splunk-SOAR/{product_version}"
DEFENDER_AUTHORIZATION_HEADER = "Bearer {token}"

DEFENDER_SOAR_BASE_URL = '{soar_base_url}rest'
DEFENDER_SOAR_SYS_INFO_URL = '/system_info'
DEFENDER_SOAR_ASSET_INFO_URL = '/asset/{asset_id}'
DEFENDER_TC_FILE = 'oauth_task.out'
DEFENDER_CONFIG_TENANT_ID = 'tenant_id'
DEFENDER_CONFIG_CLIENT_ID = 'client_id'
DEFENDER_CONFIG_CLIENT_SECRET = 'client_secret'  # pragma: allowlist secret

DEFENDER_TOKEN_STRING = 'token'
DEFENDER_ACCESS_TOKEN_STRING = 'access_token'
DEFENDER_CODE_STRING = 'code'
DEFENDER_REFRESH_TOKEN_STRING = 'refresh_token'
DEFENDER_ID_TOKEN_STRING = 'id_token'
DEFENDER_CLIENT_CREDENTIALS_STRING = 'client_credentials'
DEFENDER_BASE_URL_NOT_FOUND_MSG = 'Phantom Base URL not found in System Settings. ' \
                                     'Please specify this value in System Settings'
DEFENDER_AUTHORIZE_URL = '/{tenant_id}/oauth2/authorize?client_id={client_id}&redirect_uri={redirect_uri}' \
                            '&response_type={response_type}&state={state}&resource={resource}'
DEFENDER_RECEIVED_ALERT_INFO_MSG = 'Received alert info'
DEFENDER_HTTP_401_STATUS_CODE = '401'
DEFENDER_UNAUTHORIZED_CLIENT_ERROR_MSG = 'unauthorized_client'
DEFENDER_INVALID_TENANT_ID_FORMAT_ERROR_CODE = 'AADSTS900023'
DEFENDER_INVALID_TENANT_ID_NOT_FOUND_ERROR_CODE = 'AADSTS90002'
DEFENDER_ALERTS_ENDPOINT = '/security/alerts_v2'
DEFENDER_RUN_QUERY_ENDPOINT = '/security/runHuntingQuery'
DEFENDER_SERVER_TOKEN_URL = '/{tenant_id}/oauth2/token'
DEFENDER_LOGIN_BASE_URL = 'https://login.microsoftonline.com'
DEFENDER_RESOURCE_URL = 'https://graph.microsoft.com'
DEFENDER_MSGRAPH_API_BASE_URL = 'https://graph.microsoft.com/beta'
DEFENDER_AUTHORIZE_USER_MSG = 'Please authorize user in a separate tab using URL'
DEFENDER_GENERATING_ACCESS_TOKEN_MSG = 'Generating access token'
DEFENDER_ALERTS_INFO_MSG = 'Getting info about alerts'
DEFENDER_MAKING_CONNECTION_MSG = 'Making Connection...'
DEFENDER_TEST_CONNECTIVITY_FAILED_MSG = 'Test connectivity failed'
DEFENDER_TEST_CONNECTIVITY_PASSED_MSG = 'Test connectivity passed'
DEFENDER_OAUTH_URL_MSG = 'Using OAuth URL:'
DEFENDER_CODE_RECEIVED_MSG = 'Code Received'
DEFENDER_CLIENT_CREDENTIALS_STRING = 'client_credentials'
DEFENDER_TOKEN_NOT_AVAILABLE_MSG = 'Token not available. Please run test connectivity first'
DEFENDER_TOKEN_EXPIRED = 'Status Code: 401'
DEFENDER_STATE_FILE_CORRUPT_ERROR = "Error occurred while loading the state file due to its unexpected format. Resetting the state file with the default format. \
Please run the 'test connectivity' action again."

DEFENDER_AUTHORIZE_WAIT_TIME = 15
DEFENDER_TC_STATUS_SLEEP = 3
DEFENDER_TC_STATUS_WAIT_TIME = 105

# Constants relating to '_validate_integer'
DEFENDER_VALID_INTEGER_MSG = "Please provide a valid integer value in the {} parameter"

DEFENDER_NON_NEG_NON_ZERO_INT_MSG = (
    "Please provide a valid non-zero positive integer value in the {} parameter"
)
DEFENDER_NON_NEG_INT_MSG = "Please provide a valid non-negative integer value in the {} parameter"

# Constants relating to '_get_error_message_from_exception'
DEFENDER_ERROR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"

# For encryption and decryption
DEFENDER_ENCRYPT_TOKEN = "Encrypting the {} token"
DEFENDER_DECRYPT_TOKEN = "Decrypting the {} token"
DEFENDER_ENCRYPTION_ERROR = "Error occurred while encrypting the state file"
DEFENDER_DECRYPTION_ERROR = "Error occurred while decrypting the state file"
DEFENDER_UNEXPECTED_RESPONSE_ERROR = "Unexpected response retrieved"
DEFENDER_NO_DATA_FOUND = "No data found"
DEFENDER_STATE_IS_ENCRYPTED = 'is_encrypted'
DEFENDER_NO_PARAMETER_PROVIDED = "Please provide at least one of the property to update the alert"

DEFENDER_INCIDENT_LIMIT = 'limit'
DEFENDER_INCIDENT_OFFSET = 'offset'
DEFENDER_INCIDENT_FILTER = 'filter'
DEFENDER_INCIDENT_ORDER_BY = 'orderby'
DEFENDER_ACTION_TAKEN = 'action_taken'
DEFENDER_INCIDENT_DEFAULT_LIMIT = 50
DEFAULT_TIMEOUT = 30
DEFENDER_ALERT_DEFAULT_LIMIT = 2000
DEFENDER_INCIDENT_DEFAULT_OFFSET = 0
DEFENDER_NEXT_PAGE_TOKEN = '@odata.nextLink'
DEFENDER_LIST_INCIDENTS_ENDPOINT = '/security/incidents'

DEFENDER_INCIDENT_ID_ENDPOINT = '/security/incidents/{input}'
DEFENDER_ALERTS_ID_ENDPOINT = '/security/alerts_v2/{input}'
DEFENDER_INCIDENT_ID = 'incident_id'
DEFENDER_ALERT_ID = 'alert_id'
DEFENDER_JSON_QUERY = 'query'
DEFENDER_JSON_STATUS = 'status'
DEFENDER_JSON_ASSIGNED_TO = 'assign_to'
DEFENDER_RESPONSE_ASSIGNED_TO = 'assignedTo'
DEFENDER_JSON_CLASSIFICATION = 'classification'
DEFENDER_JSON_DETERMINATION = 'determination'

DEFENDER_RUN_CONNECTIVITY_MSG = "Please run test connectivity first to complete authorization flow and " \
    "generate a token that the app can use to make calls to the server "
DEFENDER_LIMIT_KEY = "'limit' action parameter"
DEFENDER_OFFSET_KEY = "'offset' action parameter"

DEFENDER_INVALID_CLASSIFICATION = "Please provide a valid value in the 'classification' parameter"
DEFENDER_INVALID_DETERMINATION = "Please provide a valid value in the 'determination' parameter"
DEFENDER_INVALID_STATUS = "Please provide a valid value in the 'status' parameter"
DEFENDER_SUCCESSFULLY_RETRIEVED_INCIDENT = "Successfully retrieved the incident"
DEFENDER_SUCCESSFULLY_RETRIEVED_ALERT = "Successfully retrieved the alert"
DEFENDER_NO_ALERT_FOUND = "No alert found"
DEFENDER_NO_INCIDENT_FOUND = "No incident found"
DEFENDER_ALERT_UPDATED_SUCCESSFULLY = "Successfully updated the alert"

DEFENDER_UPDATE_ALERT_USER_PARAM_LIST = [DEFENDER_JSON_STATUS, DEFENDER_JSON_ASSIGNED_TO,
             DEFENDER_JSON_CLASSIFICATION, DEFENDER_JSON_DETERMINATION]

DEFENDER_ASSET_PARAM_CHECK_LIST_ERRORS = [DEFENDER_HTTP_401_STATUS_CODE, DEFENDER_UNAUTHORIZED_CLIENT_ERROR_MSG,
    DEFENDER_INVALID_TENANT_ID_FORMAT_ERROR_CODE, DEFENDER_INVALID_TENANT_ID_NOT_FOUND_ERROR_CODE]

DEFENDER_UPDATE_ALERT_STATUS_DICT = {
    "New": "new",
    "In progress": "inProgress",
    "Resolved": "resolved"
}

DEFENDER_UPDATE_ALERT_CLASSIFICATION_DICT = {
    "Informational, expected activity": "informationalExpectedActivity",
    "False positive": "falsePositive",
    "True positive": "truePositive"
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
        "Other": "other"
}
