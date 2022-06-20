# File: microsoft_defender_consts.py
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

DEFENDER_PHANTOM_BASE_URL = '{phantom_base_url}rest'
DEFENDER_PHANTOM_SYS_INFO_URL = '/system_info'
DEFENDER_PHANTOM_ASSET_INFO_URL = '/asset/{asset_id}'
DEFENDER_TC_FILE = 'oauth_task.out'
DEFENDER_CONFIG_TENANT_ID = 'tenant_id'
DEFENDER_CONFIG_CLIENT_ID = 'client_id'
DEFENDER_CONFIG_CLIENT_SECRET = 'client_secret'  # pragma: allowlist secret

DEFENDER_TOKEN_STRING = 'token'
DEFENDER_ACCESS_TOKEN_STRING = 'access_token'
DEFENDER_REFRESH_TOKEN_STRING = 'refresh_token'
DEFENDER_ID_TOKEN_STRING = 'id_token'
DEFENDER_CLIENT_CREDENTIALS_STRING = 'client_credentials'
DEFENDER_BASE_URL_NOT_FOUND_MSG = 'Phantom Base URL not found in System Settings. ' \
                                     'Please specify this value in System Settings'
DEFENDER_AUTHORIZE_URL = '/{tenant_id}/oauth2/authorize?client_id={client_id}&redirect_uri={redirect_uri}' \
                            '&response_type={response_type}&state={state}&resource={resource}'
DEFENDER_RECEIVED_ALERT_INFO_MSG = 'Received alert info'
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
Please try again."

DEFENDER_AUTHORIZE_WAIT_TIME = 15
DEFENDER_TC_STATUS_SLEEP = 3

# Constants relating to '_validate_integer'
VALID_INTEGER_MSG = "Please provide a valid integer value in the {}"
NON_NEGATIVE_INTEGER_MSG = "Please provide a valid non-zero positive integer value in the {}"
POSITIVE_INTEGER_MSG = "Please provide non-zero positive integer in {}"

# Constants relating to '_get_error_message_from_exception'
ERR_CODE_MSG = "Error code unavailable"
ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
PARSE_ERR_MSG = "Unable to parse the error message. Please check the asset configuration and|or action parameters"
TYPE_ERR_MSG = "Error occurred while connecting to the Microsoft Defender Server." \
               " Please check the asset configuration and|or the action parameters"

# For encryption and decryption
DEFENDER_ENCRYPT_TOKEN = "Encrypting the {} token"
DEFENDER_DECRYPT_TOKEN = "Decrypting the {} token"
DEFENDER_ENCRYPTION_ERR = "Error occurred while encrypting the state file"
DEFENDER_DECRYPTION_ERR = "Error occurred while decrypting the state file"
DEFENDER_UNEXPECTED_RESPONSE_ERR = "Unexpected response retrieved"
DEFENDER_NO_DATA_FOUND = "No data found"
DEFENDER_STATE_IS_ENCRYPTED = 'is_encrypted'

DEFENDER_INCIDENT_LIMIT = 'limit'
DEFENDER_INCIDENT_OFFSET = 'offset'
DEFENDER_INCIDENT_DEFAULT_LIMIT = 50
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
DEFENDER_JSON_ASSIGNED_TO = 'assigned_to'
DEFENDER_JSON_CLASSIFICATION = 'classification'
DEFENDER_JSON_DETERMINATION = 'determination'
DEFENDER_JSON_COMMENT = 'comment'

LIMIT_KEY = "'limit' action parameter"
OFFSET_KEY = "'offset' action parameter"

DEFENDER_INVALID_CLASSIFICATION = "Please provide valid classification"
DEFENDER_INVALID_DETERMINATION = "Please provide valid determination"
DEFENDER_INVALID_STATUS = "Please provide valid status"

DEFENDER_UPDATE_ALERT_STATUS_DICT = {
    "New": "new",
    "In progress": "inProgress",
    "Resolved": "resolved"
}

DEFENDER_UPDATE_ALERT_CLASSIFICATION_DICT = {
    "Unknown": "unknown",
    "False positive": "falsePositive",
    "True positive": "truePositive"
}

DEFENDER_UPDATE_ALERT_DETERMINATION_DICT = {
    "Other": "other",
    "Multi staged attack": "multiStagedAttack",
    "Malware": "malware",
    "Malicious user activity": "maliciousUserActivity",
    "Unwanted software": "unwantedSoftware",
    "Phishing": "phishing",
    "Compromised account": "compromisedAccount",
    "Security testing": "securityTesting",
    "Confirmed activity": "confirmedActivity",
    "Line of business application": "lineOfBusinessApplication",
    "Not malicious": "notMalicious",
    "Not enough data to validate": "notEnoughDataToValidate"
}
