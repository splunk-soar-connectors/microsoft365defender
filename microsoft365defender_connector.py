# File: microsoft365defender_connector.py
#
# Copyright (c) 2022-2023 Splunk Inc.
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
#
#

import phantom.app as phantom
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

try:
    from urllib.parse import quote, urlencode
except Exception:
    from urllib import quote, urlencode

import grp
import json
import os
import pwd
import time


import encryption_helper
import requests
from bs4 import BeautifulSoup
from datetime import datetime, timedelta
from django.http import HttpResponse

from microsoft365defender_consts import *


def _handle_login_redirect(request, key):
    """ This function is used to redirect login request to Microsoft login page.

    :param request: Data given to REST endpoint
    :param key: Key to search in state file
    :return: response authorization_url/admin_consent_url
    """

    asset_id = request.GET.get('asset_id')
    if not asset_id:
        return HttpResponse('ERROR: Asset ID not found in URL', content_type="text/plain", status=400)
    state = _load_app_state(asset_id)
    if not state:
        return HttpResponse('ERROR: Invalid asset_id', content_type="text/plain", status=400)
    url = state.get(key)
    if not url:
        return HttpResponse('App state is invalid, {key} not found.'.format(key=key), content_type="text/plain", status=400)
    response = HttpResponse(status=302)
    response['Location'] = url
    return response


def _load_app_state(asset_id, app_connector=None):
    """ This function is used to load the current state file.

    :param asset_id: asset_id
    :param app_connector: Object of app_connector class
    :return: state: Current state file as a dictionary
    """

    asset_id = str(asset_id)
    if not asset_id or not asset_id.isalnum():
        if app_connector:
            app_connector.debug_print('In _load_app_state: Invalid asset_id')
        return {}

    app_dir = os.path.dirname(os.path.abspath(__file__))
    state_file = '{0}/{1}_state.json'.format(app_dir, asset_id)
    real_state_file_path = os.path.abspath(state_file)
    if not os.path.dirname(real_state_file_path) == app_dir:
        if app_connector:
            app_connector.debug_print('In _load_app_state: Invalid asset_id')
        return {}

    state = {}
    try:
        with open(real_state_file_path, 'r') as state_file_obj:
            state_file_data = state_file_obj.read()
            state = json.loads(state_file_data)
    except Exception as e:
        if app_connector:
            app_connector.debug_print('In _load_app_state: Exception: {0}'.format(str(e)))

    if app_connector:
        app_connector.debug_print('Loaded state: ', state)

    return state


def _save_app_state(state, asset_id, app_connector):
    """ This function is used to save current state in file.

    :param state: Dictionary which contains data to write in state file
    :param asset_id: asset_id
    :param app_connector: Object of app_connector class
    :return: status: phantom.APP_SUCCESS
    """

    asset_id = str(asset_id)
    if not asset_id or not asset_id.isalnum():
        if app_connector:
            app_connector.debug_print('In _save_app_state: Invalid asset_id')
        return {}

    app_dir = os.path.split(__file__)[0]
    state_file = '{0}/{1}_state.json'.format(app_dir, asset_id)

    real_state_file_path = os.path.abspath(state_file)
    if not os.path.dirname(real_state_file_path) == app_dir:
        if app_connector:
            app_connector.debug_print('In _save_app_state: Invalid asset_id')
        return {}

    if app_connector:
        app_connector.debug_print('Saving state: ', state)

    try:
        with open(real_state_file_path, 'w+') as state_file_obj:
            state_file_obj.write(json.dumps(state))
    except Exception as e:
        print('Unable to save state file: {0}'.format(str(e)))

    return phantom.APP_SUCCESS


def _handle_login_response(request):
    """ This function is used to get the login response of authorization request from Microsoft login page.

    :param request: Data given to REST endpoint
    :return: HttpResponse. The response displayed on authorization URL page
    """

    asset_id = request.GET.get('state')
    if not asset_id:
        return HttpResponse('ERROR: Asset ID not found in URL\n{}'.format(json.dumps(request.GET)), content_type="text/plain", status=400)

    # Check for error in URL
    error = request.GET.get('error')
    error_description = request.GET.get('error_description')

    # If there is an error in response
    if error:
        message = 'Error: {0}'.format(error)
        if error_description:
            message = '{0} Details: {1}'.format(message, error_description)
        return HttpResponse('Server returned {0}'.format(message), content_type="text/plain", status=400)

    code = request.GET.get(DEFENDER_CODE_STRING)

    # If code is not available
    if not code:
        return HttpResponse('Error while authenticating\n{0}'.format(json.dumps(request.GET)), content_type="text/plain", status=400)

    state = _load_app_state(asset_id)

    # If value of admin_consent is not available, value of code is available
    try:
        state[DEFENDER_CODE_STRING] = Microsoft365Defender_Connector().encrypt_state(code, asset_id=asset_id)
        state[DEFENDER_STATE_IS_ENCRYPTED] = True
    except Exception as e:
        return HttpResponse("{}: {}".format(DEFENDER_DECRYPTION_ERROR, str(e)), content_type="text/plain", status=400)

    _save_app_state(state, asset_id, None)

    return HttpResponse('Code received. Please close this window, the action will continue to get new token.', content_type="text/plain")


def _handle_rest_request(request, path_parts):
    """ Handle requests for authorization.

    :param request: Data given to REST endpoint
    :param path_parts: parts of the URL passed
    :return: dictionary containing response parameters
    """

    if len(path_parts) < 2:
        return HttpResponse('error: True, message: Invalid REST endpoint request', content_type="text/plain", status=404)

    call_type = path_parts[1]

    # To handle authorize request in test connectivity action
    if call_type == 'start_oauth':
        return _handle_login_redirect(request, 'authorization_url')

    # To handle response from microsoft login page
    if call_type == 'result':
        return_val = _handle_login_response(request)
        asset_id = request.GET.get('state')  # nosemgrep
        if asset_id and asset_id.isalnum():
            app_dir = os.path.dirname(os.path.abspath(__file__))
            auth_status_file_path = '{0}/{1}_{2}'.format(app_dir, asset_id, DEFENDER_TC_FILE)
            real_auth_status_file_path = os.path.abspath(auth_status_file_path)
            if not os.path.dirname(real_auth_status_file_path) == app_dir:
                return HttpResponse("Error: Invalid asset_id", content_type="text/plain", status=400)
            open(auth_status_file_path, 'w').close()
            try:
                uid = pwd.getpwnam('apache').pw_uid
                gid = grp.getgrnam('phantom').gr_gid
                os.chown(auth_status_file_path, uid, gid)
                os.chmod(auth_status_file_path, '0664')
            except Exception:
                pass

        return return_val
    return HttpResponse('error: Invalid endpoint', content_type="text/plain", status=404)


def _get_dir_name_from_app_name(app_name):
    """ Get name of the directory for the app.

    :param app_name: Name of the application for which directory name is required
    :return: app_name: Name of the directory for the application
    """

    app_name = ''.join([x for x in app_name if x.isalnum()])
    app_name = app_name.lower()
    if not app_name:
        app_name = 'app_for_phantom'
    return app_name


class RetVal(tuple):

    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class Microsoft365Defender_Connector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(Microsoft365Defender_Connector, self).__init__()
        import datetime
        self._execution_timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self._state = None
        self._tenant = None
        self._client_id = None
        self._access_token = None
        self._refresh_token = None
        self._client_secret = None
        self._non_interactive = None
        self.asset_id = None

    def encrypt_state(self, encrypt_var, asset_id=None):
        """ Handle encryption of token.
        :param encrypt_var: Variable needs to be encrypted
        :return: encrypted variable
        """
        if encrypt_var:
            if not asset_id:
                return encryption_helper.encrypt(encrypt_var, self.asset_id)
            return encryption_helper.encrypt(encrypt_var, asset_id)
        return encrypt_var

    def decrypt_state(self, decrypt_var):
        """ Handle decryption of token.
        :param decrypt_var: Variable needs to be decrypted
        :return: decrypted variable
        """
        if self._state.get(DEFENDER_STATE_IS_ENCRYPTED) and decrypt_var:
            return encryption_helper.decrypt(decrypt_var, self.asset_id)
        return decrypt_var

    def _process_empty_response(self, response, action_result):
        """ This function is used to process empty response.

        :param response: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        if response.status_code in [200, 204]:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(
            phantom.APP_ERROR, "Status Code: {0}. Error: Empty response and no information in the header".format(response.status_code)), None)

    def _process_html_response(self, response, action_result):
        """ This function is used to process html response.

        :param response: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            # Remove the script, style, footer and navigation part from the HTML message
            for element in soup(["script", "style", "footer", "nav"]):
                element.extract()
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except Exception:
            error_text = "Cannot parse error details"

        if not error_text:
            error_text = "Error message unavailable. Please check the asset configuration and|or the action parameters"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code, error_text)

        message = message.replace('{', '{{').replace('}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, response, action_result):
        """ This function is used to process json response.

        :param response: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        try:
            # Process a json response
            resp_json = response.json()
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}"
                                                   .format(self._get_error_message_from_exception(e))), None)

        # Please specify the status codes here
        if 200 <= response.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        message = None

        # Check whether the response contains error and error description fields
        # This condition will be used in test_connectivity
        if not isinstance(resp_json.get('error'), dict) and resp_json.get('error_description'):
            err = "Error:{0}, Error Description:{1} Please check your asset configuration parameters and run the test connectivity".format(
                    resp_json.get('error'), resp_json.get('error_description'))
            message = "Error from server. Status Code: {0} Data from server: {1}".format(response.status_code, err)

        # For other actions
        if isinstance(resp_json.get('error'), dict) and resp_json.get('error', {}).get(DEFENDER_CODE_STRING):
            msg = resp_json.get('error', {}).get('message')
            if 'text/html' in msg:
                msg = BeautifulSoup(msg, "html.parser")
                for element in msg(["title"]):
                    element.extract()
                message = "Error from server. Status Code: {0} Error Code: {1} Data from server: {2}".format(
                    response.status_code, resp_json.get('error', {}).get(DEFENDER_CODE_STRING), msg.text)
            else:
                message = "Error from server. Status Code: {0} Error Code: {1} Data from server: {2}".format(
                    response.status_code, resp_json.get('error', {}).get(DEFENDER_CODE_STRING), msg)

        if not message:
            message = "Error from server. Status Code: {0} Data from server: {1}"\
                .format(response.status_code, response.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, response, action_result):
        """ This function is used to process html response.

        :param response: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        # store the response_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': response.status_code})
            action_result.add_debug_data({'r_text': response.text})
            action_result.add_debug_data({'r_headers': response.headers})

        # Process each 'Content-Type' of response separately

        if 'json' in response.headers.get('Content-Type', ''):
            return self._process_json_response(response, action_result)

        if 'text/javascript' in response.headers.get('Content-Type', ''):
            return self._process_json_response(response, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between SOAR and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in response.headers.get('Content-Type', ''):
            return self._process_html_response(response, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not response.text:
            return self._process_empty_response(response, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            response.status_code, response.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _validate_integer(self, action_result, parameter, key, allow_zero=True):
        if parameter is not None:
            try:
                if not float(parameter).is_integer():
                    return action_result.set_status(phantom.APP_ERROR, DEFENDER_VALID_INTEGER_MSG.format(key)), None

                parameter = int(parameter)
            except Exception:
                return action_result.set_status(phantom.APP_ERROR, DEFENDER_VALID_INTEGER_MSG.format(key)), None

            # Negative value validation
            if parameter < 0:
                return action_result.set_status(phantom.APP_ERROR, DEFENDER_NON_NEG_INT_MSG.format(key)), None

            # Zero value validation
            if not allow_zero and parameter == 0:
                return action_result.set_status(phantom.APP_ERROR, DEFENDER_NON_NEG_NON_ZERO_INT_MSG.format(key)), None

        return phantom.APP_SUCCESS, parameter

    def _get_error_message_from_exception(self, e):
        """
        Get appropriate error message from the exception.
        :param e: Exception object
        :return: error message
        """

        error_code = None
        error_msg = DEFENDER_ERROR_MSG_UNAVAILABLE

        self.error_print("Error occurred.", e)

        try:
            if hasattr(e, "args"):
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_msg = e.args[1]
                elif len(e.args) == 1:
                    error_msg = e.args[0]
        except Exception:
            self.debug_print("Error occurred while fetching exception information")

        if not error_code:
            error_text = "Error Message: {}".format(error_msg)
        else:
            error_text = "Error Code: {}. Error Message: {}".format(error_code, error_msg)

        return error_text

    def _update_request(self, action_result, endpoint, headers=None, params=None, data=None, method='get'):
        """ This function is used to update the headers with access_token before making REST call.

        :param endpoint: REST endpoint that needs to appended to the service address
        :param action_result: object of ActionResult class
        :param headers: request headers
        :param params: request parameters
        :param data: request body
        :param method: GET/POST/PUT/DELETE/PATCH (Default will be GET)
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        response obtained by making an API call
        """

        if not headers:
            headers = {}

        if not self._non_interactive:
            token_data = {
                'client_id': self._client_id,
                'grant_type': DEFENDER_REFRESH_TOKEN_STRING,
                'refresh_token': self._refresh_token,
                'client_secret': self._client_secret,
                'resource': DEFENDER_RESOURCE_URL
            }
        else:
            token_data = {
                'client_id': self._client_id,
                'grant_type': DEFENDER_CLIENT_CREDENTIALS_STRING,
                'client_secret': self._client_secret,
                'resource': DEFENDER_RESOURCE_URL
            }

        if not self._access_token:
            if self._non_interactive:
                status = self._generate_new_access_token(action_result=action_result, data=token_data)

                if phantom.is_fail(status):
                    return action_result.get_status(), None

            if not self._non_interactive and not self._refresh_token:
                # If none of the access_token and refresh_token is available
                return action_result.set_status(phantom.APP_ERROR, status_message=DEFENDER_TOKEN_NOT_AVAILABLE_MSG), None

            if not self._non_interactive:
                # If refresh_token is available and access_token is not available, generate new access_token
                status = self._generate_new_access_token(action_result=action_result, data=token_data)

                if phantom.is_fail(status):
                    return action_result.get_status(), None

        headers.update({'Authorization': 'Bearer {0}'.format(self._access_token),
                        'Accept': 'application/json',
                        "User-Agent": DEFENDER_USER_AGENT.format(product_version=self.get_app_json().get('app_version')),
                        'Content-Type': 'application/json'})

        ret_val, resp_json = self._make_rest_call(action_result=action_result, endpoint=endpoint, headers=headers,
                                                  params=params, data=data, method=method)

        # If token is expired, generate new token
        if DEFENDER_TOKEN_EXPIRED in action_result.get_message():
            status = self._generate_new_access_token(action_result=action_result, data=token_data)

            if phantom.is_fail(status):
                return action_result.get_status(), None

            action_result.set_status(phantom.APP_SUCCESS, "Token generated successfully")
            headers.update({'Authorization': 'Bearer {0}'.format(self._access_token)})

            ret_val, resp_json = self._make_rest_call(action_result=action_result, endpoint=endpoint, headers=headers,
                                                      params=params, data=data, method=method)

        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        return phantom.APP_SUCCESS, resp_json

    def _make_rest_call(self, endpoint, action_result, headers=None, params=None, data=None, method="get", verify=True):
        """ Function that makes the REST call to the app.

        :param endpoint: REST endpoint that needs to appended to the service address
        :param action_result: object of ActionResult class
        :param headers: request headers
        :param params: request parameters
        :param data: request body
        :param method: GET/POST/PUT/DELETE/PATCH (Default will be GET)
        :param verify: verify server certificate (Default True)
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        response obtained by making an API call
        """

        resp_json = None
        if headers is None:
            headers = {}

        headers.update({
            "User-Agent": DEFENDER_USER_AGENT.format(product_version=self.get_app_json().get('app_version'))
        })
        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        flag = True
        while flag:
            try:
                response = request_func(endpoint, data=data, headers=headers, verify=verify, params=params, timeout=DEFAULT_TIMEOUT)
            except Exception as e:
                self.debug_print("Exception Message - {}".format(str(e)))
                return RetVal(action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. Details: {0}"
                                                    .format(self._get_error_message_from_exception(e))), resp_json)

            if response.status_code == 429 and response.headers['Retry-After']:
                retry_time = int(response.headers['Retry-After'])
                if retry_time > 300:  # throw error if wait time greater than 300 seconds
                    flag = False
                    return RetVal(action_result.set_status(phantom.APP_ERROR, "Error occured : {}, {}"
                                        .format(response.status_code, str(response.text))), resp_json)
                self.debug_print("Retrying after {} seconds".format(retry_time))
                time.sleep(retry_time + 1)
            else:
                flag = False

        return self._process_response(response, action_result)

    def _get_asset_name(self, action_result):
        """ Get name of the asset using SOAR URL.

        :param action_result: object of ActionResult class
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message), asset name
        """

        asset_id = self.get_asset_id()
        rest_endpoint = DEFENDER_SOAR_ASSET_INFO_URL.format(asset_id=asset_id)
        url = '{}{}'.format(DEFENDER_SOAR_BASE_URL.format(soar_base_url=self.get_phantom_base_url()), rest_endpoint)
        ret_val, resp_json = self._make_rest_call(action_result=action_result, endpoint=url, verify=False)

        if phantom.is_fail(ret_val):
            return ret_val, None

        asset_name = resp_json.get('name')
        if not asset_name:
            return action_result.set_status(phantom.APP_ERROR, 'Asset Name for id: {0} not found.'.format(asset_id),
                                            None)
        return phantom.APP_SUCCESS, asset_name

    def _get_phantom_base_url_defender(self, action_result):
        """ Get base url of phantom.

        :param action_result: object of ActionResult class
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        base url of phantom
        """

        url = '{}{}'.format(DEFENDER_SOAR_BASE_URL.format(soar_base_url=self.get_phantom_base_url()), DEFENDER_SOAR_SYS_INFO_URL)
        ret_val, resp_json = self._make_rest_call(action_result=action_result, endpoint=url, verify=False)
        if phantom.is_fail(ret_val):
            return ret_val, None

        soar_base_url = resp_json.get('base_url').rstrip('/')
        if not soar_base_url:
            return action_result.set_status(phantom.APP_ERROR, DEFENDER_BASE_URL_NOT_FOUND_MSG), None
        return phantom.APP_SUCCESS, soar_base_url

    def _get_app_rest_url(self, action_result):
        """ Get URL for making rest calls.

        :param action_result: object of ActionResult class
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        URL to make rest calls
        """

        ret_val, soar_base_url = self._get_phantom_base_url_defender(action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        ret_val, asset_name = self._get_asset_name(action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        self.save_progress('Using SOAR base URL as: {0}'.format(soar_base_url))
        app_json = self.get_app_json()
        app_name = app_json['name']

        app_dir_name = _get_dir_name_from_app_name(app_name)
        url_to_app_rest = '{0}/rest/handler/{1}_{2}/{3}'.format(soar_base_url, app_dir_name, app_json['appid'],
                                                                asset_name)
        return phantom.APP_SUCCESS, url_to_app_rest

    def _generate_new_access_token(self, action_result, data):
        """ This function is used to generate new access token using the code obtained on authorization.

        :param action_result: object of ActionResult class
        :param data: Data to send in REST call
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS
        """

        self.debug_print("Generating new token")
        req_url = '{}{}'.format(DEFENDER_LOGIN_BASE_URL, DEFENDER_SERVER_TOKEN_URL.format(tenant_id=quote(self._tenant)))

        ret_val, resp_json = self._make_rest_call(action_result=action_result, endpoint=req_url,
                                                  data=urlencode(data), method="post")

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if resp_json.get(DEFENDER_ID_TOKEN_STRING):
            resp_json.pop(DEFENDER_ID_TOKEN_STRING)

        try:
            self._access_token = resp_json[DEFENDER_ACCESS_TOKEN_STRING]
            if DEFENDER_REFRESH_TOKEN_STRING in resp_json:
                self._refresh_token = resp_json[DEFENDER_REFRESH_TOKEN_STRING]
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "Error occurred while generating access token {}".format(err))

        try:
            encrypted_access_token = self.encrypt_state(resp_json[DEFENDER_ACCESS_TOKEN_STRING])
            resp_json[DEFENDER_ACCESS_TOKEN_STRING] = encrypted_access_token
        except Exception as e:
            self.debug_print("{}: {}".format(DEFENDER_ENCRYPTION_ERROR, self._get_error_message_from_exception(e)))
            return action_result.set_status(phantom.APP_ERROR, DEFENDER_ENCRYPTION_ERROR)

        if DEFENDER_REFRESH_TOKEN_STRING in resp_json:
            try:
                encrypted_refresh_token = self.encrypt_state(resp_json[DEFENDER_REFRESH_TOKEN_STRING])
                resp_json[DEFENDER_REFRESH_TOKEN_STRING] = encrypted_refresh_token
            except Exception as e:
                self.debug_print("{}: {}".format(DEFENDER_ENCRYPTION_ERROR, self._get_error_message_from_exception(e)))
                return action_result.set_status(phantom.APP_ERROR, DEFENDER_ENCRYPTION_ERROR)

        self._state[DEFENDER_TOKEN_STRING] = resp_json
        self._state[DEFENDER_STATE_IS_ENCRYPTED] = True

        try:
            self.save_state(self._state)
        except Exception:
            return action_result.set_status(
                phantom.APP_ERROR,
                "Error occurred while parsing the state file. Please delete the state file and run the test connectivity again."
            )

        self._state = self.load_state()

        # Scenario -
        #
        # If the corresponding state file doesn't have correct owner, owner group or permissions,
        # the newly generated token is not being saved to state file and automatic workflow for token has been stopped.
        # So we have to check that token from response and token which are saved
        # to state file after successful generation of new token are same or not.

        if self._access_token != self.decrypt_state(self._state.get(DEFENDER_TOKEN_STRING, {}).get
                    (DEFENDER_ACCESS_TOKEN_STRING)):
            message = "Error occurred while saving the newly generated access token (in place of the expired token) in the state file."\
                      " Please check the owner, owner group, and the permissions of the state file. The SOAR user should have "\
                      "the correct access rights and ownership for the corresponding state file (refer to readme file for more information)"
            return action_result.set_status(phantom.APP_ERROR, message)

        if not self._non_interactive and self._refresh_token and self._refresh_token != self.decrypt_state(self._state.get
                    (DEFENDER_TOKEN_STRING, {}).get(DEFENDER_REFRESH_TOKEN_STRING)):
            message = "Error occurred while saving the newly generated refresh token in the state file."\
                " Please check the owner, owner group, and the permissions of the state file. The SOAR user should have "\
                "the correct access rights and ownership for the corresponding state file (refer to readme file for more information)"
            return action_result.set_status(phantom.APP_ERROR, message)

        return phantom.APP_SUCCESS

    def _wait(self, action_result):
        """ This function is used to hold the action till user login for 105 seconds.

        :param action_result: Object of ActionResult class
        :return: status (success/failed)
        """

        app_dir = os.path.dirname(os.path.abspath(__file__))
        # file to check whether the request has been granted or not
        auth_status_file_path = '{0}/{1}_{2}'.format(app_dir, self.get_asset_id(), DEFENDER_TC_FILE)
        time_out = False

        # wait-time while request is being granted for 105 seconds
        for _ in range(DEFENDER_TC_STATUS_WAIT_TIME // DEFENDER_TC_STATUS_SLEEP):
            self.send_progress('Waiting...')
            if os.path.isfile(auth_status_file_path):
                time_out = True
                os.unlink(auth_status_file_path)
                break
            time.sleep(DEFENDER_TC_STATUS_SLEEP)

        if not time_out:
            self.send_progress('')
            return action_result.set_status(phantom.APP_ERROR, "Timeout. Please try again later")
        self.send_progress('Authenticated')
        return phantom.APP_SUCCESS

    def _remove_tokens(self, action_result):
        if len(list(filter(lambda x: x in action_result.get_message(), DEFENDER_ASSET_PARAM_CHECK_LIST_ERRORS))) > 0:
            if self._state.get(DEFENDER_TOKEN_STRING, {}).get(DEFENDER_ACCESS_TOKEN_STRING):
                self._state[DEFENDER_TOKEN_STRING].pop(DEFENDER_ACCESS_TOKEN_STRING)
            if self._state.get(DEFENDER_TOKEN_STRING, {}).get(DEFENDER_REFRESH_TOKEN_STRING):
                self._state[DEFENDER_TOKEN_STRING].pop(DEFENDER_REFRESH_TOKEN_STRING)
            if self._state.get(DEFENDER_CODE_STRING):
                self._state.pop(DEFENDER_CODE_STRING)

    def _handle_test_connectivity(self, param):
        """ Testing of given credentials and obtaining authorization for all other actions.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress(DEFENDER_MAKING_CONNECTION_MSG)

        if not self._state:
            self._state = {}

        if not self._non_interactive:
            # Get initial REST URL
            ret_val, app_rest_url = self._get_app_rest_url(action_result)
            if phantom.is_fail(ret_val):
                self._remove_tokens(action_result)
                self.save_progress(DEFENDER_TEST_CONNECTIVITY_FAILED_MSG)
                return action_result.get_status()

            # Append /result to create redirect_uri
            redirect_uri = '{0}/result'.format(app_rest_url)
            self._state['redirect_uri'] = redirect_uri

            self.save_progress(DEFENDER_OAUTH_URL_MSG)
            self.save_progress(redirect_uri)

            # Authorization URL used to make request for getting code which is used to generate access token
            authorization_url = DEFENDER_AUTHORIZE_URL.format(tenant_id=quote(self._tenant), client_id=quote(self._client_id),
                                                                redirect_uri=redirect_uri, state=self.get_asset_id(),
                                                                response_type=DEFENDER_CODE_STRING, resource=DEFENDER_RESOURCE_URL)
            authorization_url = '{}{}'.format(DEFENDER_LOGIN_BASE_URL, authorization_url)

            self._state['authorization_url'] = authorization_url

            # URL which would be shown to the user
            url_for_authorize_request = '{0}/start_oauth?asset_id={1}&'.format(app_rest_url, self.get_asset_id())
            _save_app_state(self._state, self.get_asset_id(), self)

            self.save_progress(DEFENDER_AUTHORIZE_USER_MSG)
            self.save_progress(url_for_authorize_request)  # nosemgrep

            # Wait time for authorization
            time.sleep(DEFENDER_AUTHORIZE_WAIT_TIME)

            # Wait for some while user login to Microsoft
            status = self._wait(action_result=action_result)

            # Empty message to override last message of waiting
            self.send_progress('')
            if phantom.is_fail(status):
                self._remove_tokens(action_result)
                self.save_progress(DEFENDER_TEST_CONNECTIVITY_FAILED_MSG)
                return action_result.get_status()

            self.save_progress(DEFENDER_CODE_RECEIVED_MSG)
            self._state = _load_app_state(self.get_asset_id(), self)

            # if code is not available in the state file
            if not self._state or not self._state.get(DEFENDER_CODE_STRING):
                self._remove_tokens(action_result)
                return action_result.set_status(phantom.APP_ERROR, status_message=DEFENDER_TEST_CONNECTIVITY_FAILED_MSG)

            current_code = self.decrypt_state(self._state.get(DEFENDER_CODE_STRING))

        self.save_progress(DEFENDER_GENERATING_ACCESS_TOKEN_MSG)

        if not self._non_interactive:
            data = {
                'client_id': self._client_id,
                'grant_type': 'authorization_code',
                'redirect_uri': redirect_uri,
                DEFENDER_CODE_STRING: current_code,
                'resource': DEFENDER_RESOURCE_URL,
                'client_secret': self._client_secret
            }
        else:
            data = {
                'client_id': self._client_id,
                'grant_type': DEFENDER_CLIENT_CREDENTIALS_STRING,
                'client_secret': self._client_secret,
                'resource': DEFENDER_RESOURCE_URL
            }
        # For first time access, new access token is generated
        ret_val = self._generate_new_access_token(action_result=action_result, data=data)

        if phantom.is_fail(ret_val):
            self.send_progress('')
            self._remove_tokens(action_result)
            self.save_progress(DEFENDER_TEST_CONNECTIVITY_FAILED_MSG)
            return action_result.get_status()

        self.save_progress(DEFENDER_ALERTS_INFO_MSG)

        url = '{}{}'.format(DEFENDER_MSGRAPH_API_BASE_URL, DEFENDER_ALERTS_ENDPOINT)
        params = {
            '$top': 1  # page size of the result set
        }
        ret_val, _ = self._update_request(action_result=action_result, endpoint=url, params=params)
        if phantom.is_fail(ret_val):
            self.send_progress('')
            self._remove_tokens(action_result)
            self.save_progress(DEFENDER_TEST_CONNECTIVITY_FAILED_MSG)
            return action_result.get_status()

        self.save_progress(DEFENDER_RECEIVED_ALERT_INFO_MSG)
        self.save_progress(DEFENDER_TEST_CONNECTIVITY_PASSED_MSG)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _paginator(self, action_result, limit, offset, endpoint, filter, orderby):
        """
        This method is used to create an iterator that will paginate through responses from called methods.

        :param action_result: Object of ActionResult class
        :param limit: Number of resource to be returned
        :param offset: Number of resource to skip from the start
        :param endpoint: Endpoint to make REST call
        """
        resource_list = []
        next_page_token = ''

        while True:
            params = {}
            if not next_page_token and filter:
                params['$filter'] = filter
            if not next_page_token and orderby:
                params['$orderby'] = orderby
            if next_page_token:
                endpoint = next_page_token

            # First run
            if not next_page_token and offset:
                params['skip'] = offset

            # make rest call
            ret_val, response = self._update_request(endpoint=endpoint, action_result=action_result, params=params)

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            if not response:
                return action_result.set_status(phantom.APP_ERROR, DEFENDER_UNEXPECTED_RESPONSE_ERROR)
            try:
                for ele in response['value']:
                    resource_list.append(ele)
            except Exception as e:
                error_message = self._get_error_message_from_exception(e)
                self.debug_print("{}: {}".format(DEFENDER_UNEXPECTED_RESPONSE_ERROR, error_message))
                return action_result.set_status(phantom.APP_ERROR, "Error occurred while fetching data. Details: {0}"
                                                   .format(error_message))
            if not response.get(DEFENDER_NEXT_PAGE_TOKEN):
                break

            next_page_token = response[DEFENDER_NEXT_PAGE_TOKEN]

            if limit:  # If limit == None, skip this step. Could cause timeouts if no limit is defined. Used for on_poll currently
                if len(resource_list) > limit:
                    break
                
        return resource_list[:limit]

    def _handle_list_incidents(self, param):
        """ This function is used to handle the list incident action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        limit = param.get(DEFENDER_INCIDENT_LIMIT, DEFENDER_INCIDENT_DEFAULT_LIMIT)
        offset = param.get(DEFENDER_INCIDENT_OFFSET, DEFENDER_INCIDENT_DEFAULT_OFFSET)
        filter = param.get(DEFENDER_INCIDENT_FILTER)
        orderby = param.get(DEFENDER_INCIDENT_ORDER_BY)

        ret_val, limit = self._validate_integer(action_result, limit, DEFENDER_LIMIT_KEY, allow_zero=False)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        ret_val, offset = self._validate_integer(action_result, offset, DEFENDER_OFFSET_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        endpoint = "{0}{1}".format(DEFENDER_MSGRAPH_API_BASE_URL, DEFENDER_LIST_INCIDENTS_ENDPOINT)

        incident_list = self._paginator(action_result, limit, offset, endpoint, filter, orderby)

        if not incident_list and not isinstance(incident_list, list):
            return action_result.get_status()

        for incident in incident_list:
            action_result.add_data(incident)

        summary = action_result.update_summary({})
        summary['total_incidents'] = len(incident_list)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_alerts(self, param):
        """ This function is used to handle the list alert action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        limit = param.get(DEFENDER_INCIDENT_LIMIT, DEFENDER_ALERT_DEFAULT_LIMIT)
        offset = param.get(DEFENDER_INCIDENT_OFFSET, DEFENDER_INCIDENT_DEFAULT_OFFSET)
        filter = param.get(DEFENDER_INCIDENT_FILTER)
        orderby = param.get(DEFENDER_INCIDENT_ORDER_BY)

        ret_val, limit = self._validate_integer(action_result, limit, DEFENDER_LIMIT_KEY, allow_zero=False)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        ret_val, offset = self._validate_integer(action_result, offset, DEFENDER_OFFSET_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        endpoint = "{0}{1}".format(DEFENDER_MSGRAPH_API_BASE_URL, DEFENDER_ALERTS_ENDPOINT)
        alert_list = self._paginator(action_result, limit, offset, endpoint, filter, orderby)

        if not alert_list and not isinstance(alert_list, list):
            return action_result.get_status()

        for incident in alert_list:
            action_result.add_data(incident)

        summary = action_result.update_summary({})
        summary['total_alerts'] = len(alert_list)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_incident(self, param):
        """ This function is used to handle the get incident action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        incident_id = param[DEFENDER_INCIDENT_ID]

        endpoint = "{0}{1}".format(DEFENDER_MSGRAPH_API_BASE_URL, DEFENDER_INCIDENT_ID_ENDPOINT
                                   .format(input=incident_id))

        # make rest call
        ret_val, response = self._update_request(endpoint=endpoint, action_result=action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS, DEFENDER_SUCCESSFULLY_RETRIEVED_INCIDENT)

    def _handle_get_alert(self, param):
        """ This function is used to handle the get alert action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        alert_id = param[DEFENDER_ALERT_ID]

        endpoint = "{0}{1}".format(DEFENDER_MSGRAPH_API_BASE_URL, DEFENDER_ALERTS_ID_ENDPOINT
                                   .format(input=alert_id))

        # make rest call
        ret_val, response = self._update_request(endpoint=endpoint, action_result=action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS, DEFENDER_SUCCESSFULLY_RETRIEVED_ALERT)

    def _handle_run_query(self, param):
        """ This function is used to handle the run query action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        query = param[DEFENDER_JSON_QUERY]

        # prepare data parameters
        data = {
            "Query": query
        }

        endpoint = "{0}{1}".format(DEFENDER_MSGRAPH_API_BASE_URL, DEFENDER_RUN_QUERY_ENDPOINT)

        # make rest call
        ret_val, response = self._update_request(endpoint=endpoint, action_result=action_result, data=json.dumps(data), method="post")

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        results = response.get('results', [])
        len_results = len(results)

        for result in results:
            action_result.add_data(result)

        summary = action_result.update_summary({})
        summary['total_results'] = len_results

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_update_alert(self, param):
        """ This function is used to handle the update alert action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        alert_id = param[DEFENDER_ALERT_ID]

        if not any(param.get(x) for x in DEFENDER_UPDATE_ALERT_USER_PARAM_LIST):
            return action_result.set_status(phantom.APP_ERROR, DEFENDER_NO_PARAMETER_PROVIDED)

        endpoint = "{0}{1}".format(DEFENDER_MSGRAPH_API_BASE_URL, DEFENDER_ALERTS_ID_ENDPOINT
                                   .format(input=alert_id))

        # make rest call
        ret_val, response = self._update_request(endpoint=endpoint, action_result=action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        request_body = {}

        status = param.get(DEFENDER_JSON_STATUS, response.get(DEFENDER_JSON_STATUS))
        assigned_to = param.get(DEFENDER_JSON_ASSIGNED_TO, response.get(DEFENDER_RESPONSE_ASSIGNED_TO))
        classification = param.get(DEFENDER_JSON_CLASSIFICATION, response.get(DEFENDER_JSON_CLASSIFICATION))
        determination = param.get(DEFENDER_JSON_DETERMINATION, response.get(DEFENDER_JSON_DETERMINATION))

        if status:
            if param.get(DEFENDER_JSON_STATUS):
                if status not in DEFENDER_UPDATE_ALERT_STATUS_DICT.keys():
                    return action_result.set_status(phantom.APP_ERROR, DEFENDER_INVALID_STATUS)
                else:
                    request_body[DEFENDER_JSON_STATUS] = DEFENDER_UPDATE_ALERT_STATUS_DICT[status]
            else:
                request_body[DEFENDER_JSON_STATUS] = status

        if assigned_to:
            request_body[DEFENDER_RESPONSE_ASSIGNED_TO] = assigned_to

        if classification:
            if param.get(DEFENDER_JSON_CLASSIFICATION):
                if classification not in DEFENDER_UPDATE_ALERT_CLASSIFICATION_DICT.keys():
                    return action_result.set_status(phantom.APP_ERROR, DEFENDER_INVALID_CLASSIFICATION)
                else:
                    request_body[DEFENDER_JSON_CLASSIFICATION] = DEFENDER_UPDATE_ALERT_CLASSIFICATION_DICT[classification]
            else:
                request_body[DEFENDER_JSON_CLASSIFICATION] = classification

        if determination:
            if param.get(DEFENDER_JSON_DETERMINATION):
                if determination not in DEFENDER_UPDATE_ALERT_DETERMINATION_DICT.keys():
                    return action_result.set_status(phantom.APP_ERROR, DEFENDER_INVALID_DETERMINATION)
                else:
                    request_body[DEFENDER_JSON_DETERMINATION] = DEFENDER_UPDATE_ALERT_DETERMINATION_DICT[determination]
            else:
                request_body[DEFENDER_JSON_DETERMINATION] = determination

        endpoint = "{0}{1}".format(DEFENDER_MSGRAPH_API_BASE_URL, DEFENDER_ALERTS_ID_ENDPOINT
                                   .format(input=alert_id))
        # make rest call
        ret_val, response = self._update_request(endpoint=endpoint, action_result=action_result, method="patch",
                                                 data=json.dumps(request_body))

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS, DEFENDER_ALERT_UPDATED_SUCCESSFULLY)

    def _handle_on_poll(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        config = self.get_config()
        
        # TODO: These parameters are not currently being passed to on_poll. Will use defaults, at least for now
        limit = None
        offset = 0
        filter = param.get(DEFENDER_INCIDENT_FILTER)
        orderby = param.get(DEFENDER_INCIDENT_ORDER_BY)
        start_time_scheduled_poll = config.get(DEFENDER_CONFIG_START_TIME_SCHEDULED_POLL)
        last_modified_time = (datetime.now() - timedelta(days=7)).strftime(DEFENDER_DT_STR_FORMAT)  # Let's fall back to the last 7 days
        self._max_artifacts = config.get("max_artifacts", DEFENDER_CONFIG_MAX_ARTIFACTS_DEFAULT)
        max_incidents = DEFENDER_INCIDENT_DEFAULT_LIMIT


        if start_time_scheduled_poll:
            ret_val = self._check_date_format(action_result, start_time_scheduled_poll)
            if phantom.is_fail(ret_val):
                self.save_progress(action_result.get_message())
                return action_result.set_status(phantom.APP_ERROR)
            last_modified_time = start_time_scheduled_poll

        if self.is_poll_now():
            max_incidents = int(param.get(phantom.APP_JSON_CONTAINER_COUNT))
        elif self._state.get(STATE_FIRST_RUN, True):
            self._state[STATE_FIRST_RUN] = False
            max_incidents = int(config.get(DEFENDER_CONFIG_FIRST_RUN_MAX_INCIDENTS, max_incidents))
        else:
            if self._state.get(STATE_LAST_TIME):
                last_modified_time = self._state[STATE_LAST_TIME]

        endpoint = "{0}{1}".format(DEFENDER_MSGRAPH_API_BASE_URL, DEFENDER_LIST_INCIDENTS_ENDPOINT)
        endpoint += "?$expand=alerts"
        incident_list = self._paginator(action_result, limit, offset, endpoint, filter, orderby)
        if not incident_list:  # Failed to fetch incidents, regardless of the reason
            self.save_progress("Failed to retrieve incidents")
            return action_result.get_status()

        self.save_progress(f"Successfully fetched {len(incident_list)} incidents.")

        # Ingest the incidents
        for incident in incident_list:
            try:
                # Get alerts for this incident
                alerts = incident.pop('alerts')
            except KeyError:
                alerts = []
                
            try:                
                # Create artifact from the incident
                artifacts = self._create_incident_artifacts(action_result, incident)
            except Exception as e:
                self.debug_print("Error occurred while creating artifacts for incidents. Error: {}".format(str(e)))
                # Make incidents as empty list
                incident_list = list()
            
            if alerts:
                for alert in alerts:
                    try:
                        artifacts.append(self._create_alert_artifacts(action_result, alert)[0])  # TODO: What are the corner cases that can make this fail?
                    except Exception as e:
                        self.debug_print("Error occurred while creating artifacts for alerts. Error: {}".format(str(e)))
                        # Make alerts as empty list
                        alert_list = list()
            
            # Ingest artifacts for incidents and alerts
            try:
                self._ingest_artifacts_new(action_result, artifacts, name=incident["displayName"], key=incident["id"])
            except Exception as e:
                self.debug_print("Error occurred while saving artifacts for incidents. Error: {}".format(str(e)))

        summary = action_result.update_summary({})
        summary["total_incidents"] = len(incident_list)
        summary["filter"] = filter
        summary["first_run"] = self._state.get(STATE_FIRST_RUN, True)

        if incident_list:
            if DEFENDER_JSON_LAST_MODIFIED not in incident_list[0]:
                return action_result.set_status(phantom.APP_ERROR, f"Could not extract {DEFENDER_JSON_LAST_MODIFIED} from latest ingested incident.")

            self._state[STATE_LAST_TIME] = incident_list[0][DEFENDER_JSON_LAST_MODIFIED]
            self.save_state(self._state)

        return action_result.set_status(phantom.APP_SUCCESS)
    
    def _check_for_existing_container(self, action_result, key):
        """Check for existing container and return container ID and remaining margin count.
        Parameters:
            :param action_result: object of ActionResult class
            :param key: Source Data ID of the container to check
        Returns:
            :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR),
                    cid(container_id),
                    count(remaining margin calculated with given _max_artifacts)
        """
        cid = None
        count = None

        base_url = self.get_phantom_base_url()
        base_url = base_url if base_url.endswith('/') else base_url + '/'
        url = f'{base_url}rest/container?_filter_source_data_identifier="{key}"&sort=start_time&order=desc'

        try:
            r = requests.get(url, verify=False)
        except Exception as e:
            self.debug_print("Error making local rest call: {0}".format(str(e)))
            self.debug_print('DB QUERY: {}'.format(url))
            return phantom.APP_ERROR, cid, count

        try:
            resp_json = r.json()
        except Exception as e:
            self.debug_print('Exception caught: {0}'.format(str(e)))
            return phantom.APP_ERROR, cid, count

        container = resp_json.get('data', [])
        if not container:
            self.debug_print("Not having any existing container")
            return phantom.APP_ERROR, cid, count

        # Consider latest container as existing container from the received list of containers
        try:
            container = container[0]
            if not isinstance(container, dict):
                self.debug_print("Invalid response received while checking for the existing container")
                return phantom.APP_ERROR, cid, count
        except Exception as e:
            self.debug_print("Invalid response received while checking for the existing container. Error: {}".format(str(e)))
            return phantom.APP_ERROR, cid, count

        cid = container.get('id')
        artifact_count = container.get('artifact_count')

        self.debug_print("Existing Container ID: {}".format(cid))
        self.debug_print("Existing Container artifacts count: {}".format(artifact_count))

        try:
            count = int(self._max_artifacts) - int(artifact_count)
            # Not having space in latest container or exceed a configured limit for artifacts
            if count <= 0:
                self.debug_print("Not having enough space for the artifacts in the existing container")
                cid = None
                count = None
        except Exception as e:
            self.debug_print("Error occurred while calculating remaining container space. Error: {}".format(str(e)))
            cid = None
            count = None
        return phantom.APP_SUCCESS, cid, count

    def _ingest_artifacts_new(self, action_result, artifacts, name, key, cid=None):
        """Save the artifacts into the given container ID(cid) and if not given create new container with given key(name).
        Parameters:
            :param action_result: object of ActionResult class
            :param artifacts: list of artifacts of IoCs or incidents results
            :param name: name of the container in which data will be ingested
            :param key: source ID of the container in which data will be ingested
            :param cid: value of container ID
        Returns:
            :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR), message, cid(container_id)
        """
        
        # Check for existing container only if it's a scheduled/interval poll and not first run
        if not (self.is_poll_now() or self._state['first_run']):
            ret_val, cid, count = self._check_for_existing_container(action_result, key)
            if phantom.is_fail(ret_val):
                self.debug_print("Failed to check for existing container")

        if not cid:
            container = dict()
            container.update({
                "name": name,
                "description": 'incident ingested using MS Defender API',
                "source_data_identifier": key
            })

            ret_val, message, cid = self.save_container(container)
            self.debug_print("save_container (with artifacts) returns, value: {}, reason: {}, id: {}".format(ret_val, message, cid))

        artifacts[-1]["run_automation"] = True
        for artifact in artifacts:
            artifact['container_id'] = cid
        ret_val, message, _ = self.save_artifacts(artifacts)

        self.debug_print("save_artifacts returns, value: {}, reason: {}".format(ret_val, message))
        return ret_val, message, cid
    
    # TODO: Merge the 2 functions below, as they are too similar
    def _create_alert_artifacts(self, action_result, alert):
        artifacts = []

        alert_artifact = {}
        alert_artifact['label'] = 'alert'
        alert_artifact['name'] = alert.get('title')
        alert_artifact['source_data_identifier'] = alert.get('id')
        alert_artifact['data'] = alert
        alert_artifact['cef'] = alert
        
        artifacts.append(alert_artifact)

        return artifacts
    
    def _create_incident_artifacts(self, action_result, incident):
        artifacts = []

        incident_artifact = {}
        incident_artifact['label'] = 'incident'
        incident_artifact['name'] = 'incident Artifact'
        incident_artifact['source_data_identifier'] = incident.get('id')
        incident_artifact['data'] = incident
        incident_artifact['cef'] = incident

        artifacts.append(incident_artifact)

        return artifacts

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)
        elif action_id == 'list_incidents':
            ret_val = self._handle_list_incidents(param)
        elif action_id == 'list_alerts':
            ret_val = self._handle_list_alerts(param)
        elif action_id == 'get_incident':
            ret_val = self._handle_get_incident(param)
        elif action_id == 'get_alert':
            ret_val = self._handle_get_alert(param)
        elif action_id == 'run_query':
            ret_val = self._handle_run_query(param)
        elif action_id == 'update_alert':
            ret_val = self._handle_update_alert(param)
        elif action_id == 'on_poll':
            ret_val = self._handle_on_poll(param)

        return ret_val

    def initialize(self):
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        action_id = self.get_action_identifier()
        action_result = ActionResult()
        self.asset_id = self.get_asset_id()
        self._non_interactive = config.get('non_interactive', False)
        self._tenant = config[DEFENDER_CONFIG_TENANT_ID]
        self._client_id = config[DEFENDER_CONFIG_CLIENT_ID]
        self._client_secret = config[DEFENDER_CONFIG_CLIENT_SECRET]

        if not isinstance(self._state, dict):
            self.debug_print("Resetting the state file with the default format")
            self._state = {
                "app_version": self.get_app_json().get('app_version')
            }
            if not self._non_interactive:
                return self.set_status(phantom.APP_ERROR, DEFENDER_STATE_FILE_CORRUPT_ERROR)

        self._access_token = self._state.get(DEFENDER_TOKEN_STRING, {}).get(DEFENDER_ACCESS_TOKEN_STRING, None)
        if self._state.get(DEFENDER_STATE_IS_ENCRYPTED):
            try:
                if self._access_token:
                    self._access_token = self.decrypt_state(self._access_token)
            except Exception as e:
                self.debug_print("{}: {}".format(DEFENDER_DECRYPTION_ERROR, self._get_error_message_from_exception(e)))
                self._access_token = None

        self._refresh_token = self._state.get(DEFENDER_TOKEN_STRING, {}).get(DEFENDER_REFRESH_TOKEN_STRING, None)
        if self._state.get(DEFENDER_STATE_IS_ENCRYPTED):
            try:
                if self._refresh_token:
                    self._refresh_token = self.decrypt_state(self._refresh_token)
            except Exception as e:
                self.debug_print("{}: {}".format(DEFENDER_DECRYPTION_ERROR, self._get_error_message_from_exception(e)))
                self._refresh_token = None

        if not self._non_interactive and action_id != 'test_connectivity' and (not self._access_token or not self._refresh_token):
            token_data = {
                'client_id': self._client_id,
                'grant_type': DEFENDER_REFRESH_TOKEN_STRING,
                'refresh_token': self._refresh_token,
                'client_secret': self._client_secret,
                'resource': DEFENDER_RESOURCE_URL
            }
            ret_val = self._generate_new_access_token(action_result=action_result, data=token_data)

            if phantom.is_fail(ret_val):
                return self.set_status(phantom.APP_ERROR, "{0}. {1}".format(DEFENDER_RUN_CONNECTIVITY_MSG, action_result.get_message()))

        return phantom.APP_SUCCESS

    def finalize(self):
        try:
            if self._state.get(DEFENDER_TOKEN_STRING, {}).get(DEFENDER_ACCESS_TOKEN_STRING):
                self._state[DEFENDER_TOKEN_STRING][DEFENDER_ACCESS_TOKEN_STRING] = self.encrypt_state(self._access_token)
        except Exception as e:
            self.debug_print("{}: {}".format(DEFENDER_ENCRYPTION_ERROR, self._get_error_message_from_exception(e)))
            return self.set_status(phantom.APP_ERROR, DEFENDER_ENCRYPTION_ERROR)

        try:
            if self._state.get(DEFENDER_TOKEN_STRING, {}).get(DEFENDER_REFRESH_TOKEN_STRING):
                self._state[DEFENDER_TOKEN_STRING][DEFENDER_REFRESH_TOKEN_STRING] = self.encrypt_state(self._refresh_token)
        except Exception as e:
            self.debug_print("{}: {}".format(DEFENDER_ENCRYPTION_ERROR, self._get_error_message_from_exception(e)))
            return self.set_status(phantom.APP_ERROR, DEFENDER_ENCRYPTION_ERROR)

        if not self._state.get(DEFENDER_STATE_IS_ENCRYPTED):
            try:
                if self._state.get(DEFENDER_CODE_STRING):
                    self._state[DEFENDER_CODE_STRING] = self.encrypt_state(self._state[DEFENDER_CODE_STRING])
            except Exception as e:
                self.debug_print("{}: {}".format(DEFENDER_ENCRYPTION_ERROR, self._get_error_message_from_exception(e)))
                return self.set_status(phantom.APP_ERROR, DEFENDER_ENCRYPTION_ERROR)
            if self._state.get(DEFENDER_TOKEN_STRING, {}).get(DEFENDER_ID_TOKEN_STRING):
                self._state[DEFENDER_TOKEN_STRING].pop(DEFENDER_ID_TOKEN_STRING)

        # Save the state, this data is saved across actions and app upgrades
        self._state[DEFENDER_STATE_IS_ENCRYPTED] = True
        self.save_state(self._state)
        return phantom.APP_SUCCESS


def main():
    import argparse
    import sys

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)
    argparser.add_argument('-v', '--verify', action='store_true', help='verify', required=False, default=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password
    verify = args.verify

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = "{}login".format(BaseConnector._get_phantom_base_url())

            print("Accessing the Login page")
            r = requests.get(login_url, verify=verify, timeout=DEFAULT_TIMEOUT)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken={}'.format(csrftoken)
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=verify, data=data, headers=headers, timeout=DEFAULT_TIMEOUT)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platform. Error: {0}".format(str(e)))
            sys.exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = Microsoft365Defender_Connector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    sys.exit(0)


if __name__ == '__main__':
    main()
