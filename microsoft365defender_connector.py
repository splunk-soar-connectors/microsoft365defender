# File: microsoft365defender_connector.py
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
#
#
# Phantom App imports

import phantom.app as phantom
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

try:
    from urllib.parse import quote, urlencode
except Exception:
    from urllib import quote, urlencode

# Usage of the consts file is recommended
import grp
import json
import os
import pwd
import time

import encryption_helper
import requests
from bs4 import BeautifulSoup
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

    code = request.GET.get('code')

    # If code is not available
    if not code:
        return HttpResponse('Error while authenticating\n{0}'.format(json.dumps(request.GET)), content_type="text/plain", status=400)

    state = _load_app_state(asset_id)

    # If value of admin_consent is not available, value of code is available
    try:
        state['code'] = Microsoft365Defender_Connector().encrypt_state(code, "code")
        state[DEFENDER_STATE_IS_ENCRYPTED] = True
    except Exception as e:
        return HttpResponse("{}: {}".format(DEFENDER_DECRYPTION_ERR, str(e)), content_type="text/plain", status=400)

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
        asset_id = request.GET.get('state')
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

        self._state = None
        self._tenant = None
        self._client_id = None
        self._access_token = None
        self._refresh_token = None
        self._client_secret = None
        self._non_interactive = None
        self.asset_id = self.get_asset_id()

    def encrypt_state(self, encrypt_var, token_name):
        """ Handle encryption of token.
        :param encrypt_var: Variable needs to be encrypted
        :return: encrypted variable
        """
        self.debug_print(DEFENDER_ENCRYPT_TOKEN.format(token_name))  # nosemgrep
        return encryption_helper.encrypt(encrypt_var, self.asset_id)

    def decrypt_state(self, decrypt_var, token_name):
        """ Handle decryption of token.
        :param decrypt_var: Variable needs to be decrypted
        :return: decrypted variable
        """
        self.debug_print(DEFENDER_DECRYPT_TOKEN.format(token_name))  # nosemgrep
        if self._state.get(DEFENDER_STATE_IS_ENCRYPTED):
            return encryption_helper.decrypt(decrypt_var, self.asset_id)
        return decrypt_var

    def _process_empty_response(self, response, action_result):
        """ This function is used to process empty response.

        :param response: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        if response.status_code == 200 or response.status_code == 204:
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
        if isinstance(resp_json.get('error'), dict) and resp_json.get('error', {}).get('code'):
            msg = resp_json.get('error', {}).get('message')
            if 'text/html' in msg:
                msg = BeautifulSoup(msg, "html.parser")
                for element in msg(["title"]):
                    element.extract()
                message = "Error from server. Status Code: {0} Error Code: {1} Data from server: {2}".format(
                    response.status_code, resp_json.get('error', {}).get('code'), msg.text)
            else:
                message = "Error from server. Status Code: {0} Error Code: {1} Data from server: {2}".format(
                    response.status_code, resp_json.get('error', {}).get('code'), msg)

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
        # There is a high chance of a PROXY in between phantom and the rest of
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
                    return action_result.set_status(phantom.APP_ERROR, VALID_INTEGER_MSG.format(key)), None

                parameter = int(parameter)
            except Exception:
                return action_result.set_status(phantom.APP_ERROR, VALID_INTEGER_MSG.format(key)), None

            # Negative value validation
            if parameter < 0:
                return action_result.set_status(phantom.APP_ERROR, NON_NEGATIVE_INTEGER_MSG.format(key)), None

            # Zero value validation
            if not allow_zero and parameter == 0:
                return action_result.set_status(phantom.APP_ERROR, POSITIVE_INTEGER_MSG.format(key)), None

        return phantom.APP_SUCCESS, parameter

    def _get_error_message_from_exception(self, e):
        """
        Get appropriate error message from the exception.
        :param e: Exception object
        :return: error message
        """

        error_code = None
        error_msg = ERR_MSG_UNAVAILABLE

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
                return action_result.set_status(phantom.APP_ERROR, status_message=DEFENDER_TOKEN_NOT_AVAILABLE_MSG), None
            if not self._non_interactive and not self._refresh_token:
                # If none of the access_token and refresh_token is available
                return action_result.set_status(phantom.APP_ERROR, status_message=DEFENDER_TOKEN_NOT_AVAILABLE_MSG), None

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

        try:
            response = request_func(endpoint, data=data, headers=headers, verify=verify, params=params, timeout=DEFAULT_TIMEOUT)
        except Exception as e:
            try:
                self.debug_print("make_rest_call exception...")
                self.debug_print("Exception Message - {}".format(e))
                self.debug_print("make_rest_call exception ends...")
            except Exception:
                self.debug_print("Error occurred while logging the make_rest_call exception message")

            return RetVal(action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. Details: {0}"
                                                   .format(self._get_error_message_from_exception(e))), resp_json)

        return self._process_response(response, action_result)

    def _get_asset_name(self, action_result):
        """ Get name of the asset using Phantom URL.

        :param action_result: object of ActionResult class
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message), asset name
        """

        asset_id = self.get_asset_id()
        rest_endpoint = DEFENDER_PHANTOM_ASSET_INFO_URL.format(asset_id=asset_id)
        url = '{}{}'.format(DEFENDER_PHANTOM_BASE_URL.format(phantom_base_url=self.get_phantom_base_url()), rest_endpoint)
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

        url = '{}{}'.format(DEFENDER_PHANTOM_BASE_URL.format(phantom_base_url=self.get_phantom_base_url()), DEFENDER_PHANTOM_SYS_INFO_URL)
        ret_val, resp_json = self._make_rest_call(action_result=action_result, endpoint=url, verify=False)
        if phantom.is_fail(ret_val):
            return ret_val, None

        phantom_base_url = resp_json.get('base_url').rstrip('/')
        if not phantom_base_url:
            return action_result.set_status(phantom.APP_ERROR, DEFENDER_BASE_URL_NOT_FOUND_MSG), None
        return phantom.APP_SUCCESS, phantom_base_url

    def _get_app_rest_url(self, action_result):
        """ Get URL for making rest calls.

        :param action_result: object of ActionResult class
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        URL to make rest calls
        """

        ret_val, phantom_base_url = self._get_phantom_base_url_defender(action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        ret_val, asset_name = self._get_asset_name(action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        self.save_progress('Using Phantom base URL as: {0}'.format(phantom_base_url))
        app_json = self.get_app_json()
        app_name = app_json['name']

        app_dir_name = _get_dir_name_from_app_name(app_name)
        url_to_app_rest = '{0}/rest/handler/{1}_{2}/{3}'.format(phantom_base_url, app_dir_name, app_json['appid'],
                                                                asset_name)
        return phantom.APP_SUCCESS, url_to_app_rest

    def _generate_new_access_token(self, action_result, data):
        """ This function is used to generate new access token using the code obtained on authorization.

        :param action_result: object of ActionResult class
        :param data: Data to send in REST call
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS
        """

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
            encrypted_access_token = self.encrypt_state(resp_json[DEFENDER_ACCESS_TOKEN_STRING], "access")
            resp_json[DEFENDER_ACCESS_TOKEN_STRING] = encrypted_access_token
        except Exception as e:
            self.debug_print("{}: {}".format(DEFENDER_ENCRYPTION_ERR, self._get_error_message_from_exception(e)))
            return action_result.set_status(phantom.APP_ERROR, DEFENDER_ENCRYPTION_ERR)

        if DEFENDER_REFRESH_TOKEN_STRING in resp_json:
            try:
                encrypted_refresh_token = self.encrypt_state(resp_json[DEFENDER_REFRESH_TOKEN_STRING], "refresh")
                resp_json[DEFENDER_REFRESH_TOKEN_STRING] = encrypted_refresh_token
            except Exception as e:
                self.debug_print("{}: {}".format(DEFENDER_ENCRYPTION_ERR, self._get_error_message_from_exception(e)))
                return action_result.set_status(phantom.APP_ERROR, DEFENDER_ENCRYPTION_ERR)

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
                    (DEFENDER_ACCESS_TOKEN_STRING), "access"):
            message = "Error occurred while saving the newly generated access token (in place of the expired token) in the state file."\
                      " Please check the owner, owner group, and the permissions of the state file. The Phantom user should have "\
                      "the correct access rights and ownership for the corresponding state file (refer to readme file for more information)"
            return action_result.set_status(phantom.APP_ERROR, message)

        if self._refresh_token and self._refresh_token != self.decrypt_state(self._state.get
                    (DEFENDER_TOKEN_STRING, {}).get(DEFENDER_REFRESH_TOKEN_STRING), "refresh"):
            message = "Error occurred while saving the newly generated refresh token in the state file."\
                " Please check the owner, owner group, and the permissions of the state file. The Phantom user should have "\
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
        for _ in range(0, 35):
            self.send_progress('Waiting...')
            self._state = _load_app_state(self.get_asset_id(), self)
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
                                                                response_type='code', resource=DEFENDER_RESOURCE_URL)
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
                self.save_progress(DEFENDER_TEST_CONNECTIVITY_FAILED_MSG)
                return action_result.get_status()

            self.save_progress(DEFENDER_CODE_RECEIVED_MSG)
            self._state = _load_app_state(self.get_asset_id(), self)

            # if code is not available in the state file
            if not self._state or not self._state.get('code'):
                return action_result.set_status(phantom.APP_ERROR, status_message=DEFENDER_TEST_CONNECTIVITY_FAILED_MSG)

            current_code = self.decrypt_state(self._state.get('code'), "code")

        self.save_progress(DEFENDER_GENERATING_ACCESS_TOKEN_MSG)

        if not self._non_interactive:
            data = {
                'client_id': self._client_id,
                'grant_type': 'authorization_code',
                'redirect_uri': redirect_uri,
                'code': current_code,
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
            self.save_progress(DEFENDER_TEST_CONNECTIVITY_FAILED_MSG)
            return action_result.get_status()

        self.save_progress(DEFENDER_ALERTS_INFO_MSG)

        url = '{}{}'.format(DEFENDER_MSGRAPH_API_BASE_URL, DEFENDER_ALERTS_ENDPOINT)
        params = {
            '$top': 1
        }
        ret_val, _ = self._update_request(action_result=action_result, endpoint=url, params=params)
        if phantom.is_fail(ret_val):
            self.send_progress('')
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
                return action_result.set_status(phantom.APP_ERROR, DEFENDER_UNEXPECTED_RESPONSE_ERR)
            try:
                for ele in response['value']:
                    resource_list.append(ele)
            except Exception as e:
                err_msg = self._get_error_message_from_exception(e)
                self.debug_print("{}: {}".format(DEFENDER_UNEXPECTED_RESPONSE_ERR, err_msg))
                return action_result.set_status(phantom.APP_ERROR, "Error occurred while fetching data. Details: {0}"
                                                   .format(err_msg))
            if not response.get(DEFENDER_NEXT_PAGE_TOKEN):
                break

            next_page_token = response[DEFENDER_NEXT_PAGE_TOKEN]

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

        ret_val, limit = self._validate_integer(action_result, limit, LIMIT_KEY, allow_zero=False)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        ret_val, offset = self._validate_integer(action_result, offset, OFFSET_KEY)
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

        ret_val, limit = self._validate_integer(action_result, limit, LIMIT_KEY, allow_zero=False)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        ret_val, offset = self._validate_integer(action_result, offset, OFFSET_KEY)
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

        if not response:
            return action_result.set_status(phantom.APP_SUCCESS, DEFENDER_NO_INCIDENT_FOUND)

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

        if not response:
            return action_result.set_status(phantom.APP_SUCCESS, DEFENDER_NO_ALERT_FOUND)

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

        if not response:
            return action_result.set_status(phantom.APP_ERROR, DEFENDER_NO_DATA_FOUND)

        results = response.get('results', [])
        len_results = len(results)

        for result in results:
            action_result.add_data(result)

        summary = action_result.update_summary({})
        summary['total_results'] = len_results

        return action_result.set_status(phantom.APP_SUCCESS)

    def remove_spaces(self, param):
        """ This function is used to remove the spaces from the param name.

        :param param: String of param to remove spaces from
        :return: param(String) of removed spaces
        """
        fields_list = [x.strip() for x in param.split(" ")]
        fields_list = list(filter(None, fields_list))
        param = ''.join(fields_list)
        return param

    def _handle_update_alert(self, param):
        """ This function is used to handle the update alert action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        alert_id = param[DEFENDER_ALERT_ID]
        status = param.get(DEFENDER_JSON_STATUS)
        assigned_to = param.get(DEFENDER_JSON_ASSIGNED_TO)
        classification = param.get(DEFENDER_JSON_CLASSIFICATION)
        determination = param.get(DEFENDER_JSON_DETERMINATION)
        comment = param.get(DEFENDER_JSON_COMMENT)

        request_body = {}

        if status:
            status = self.remove_spaces(status)
            if status.lower() not in DEFENDER_UPDATE_ALERT_STATUS_DICT.keys():
                return action_result.set_status(phantom.APP_ERROR, DEFENDER_INVALID_STATUS)
            request_body["status"] = DEFENDER_UPDATE_ALERT_STATUS_DICT[status]

        if assigned_to:
            request_body["assignedTo"] = assigned_to

        if classification:
            classification = self.remove_spaces(classification)
            if classification.lower() not in DEFENDER_UPDATE_ALERT_CLASSIFICATION_DICT.keys():
                return action_result.set_status(phantom.APP_ERROR, DEFENDER_INVALID_CLASSIFICATION)
            request_body["classification"] = DEFENDER_UPDATE_ALERT_CLASSIFICATION_DICT[classification]

        if determination:
            determination = self.remove_spaces(determination)
            if determination.lower() not in DEFENDER_UPDATE_ALERT_DETERMINATION_DICT.keys():
                return action_result.set_status(phantom.APP_ERROR, DEFENDER_INVALID_DETERMINATION)
            request_body["determination"] = DEFENDER_UPDATE_ALERT_DETERMINATION_DICT[determination]

        if comment:
            request_body["comment"] = comment

        endpoint = "{0}{1}".format(DEFENDER_MSGRAPH_API_BASE_URL, DEFENDER_ALERTS_ID_ENDPOINT
                                   .format(input=alert_id))

        if not request_body:
            return action_result.set_status(phantom.APP_ERROR, DEFENDER_NO_PARAMETER_PROVIDED)

        # make rest call
        ret_val, response = self._update_request(endpoint=endpoint, action_result=action_result, method="patch",
                                                 data=json.dumps(request_body))

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if not response:
            return action_result.set_status(phantom.APP_SUCCESS, DEFENDER_NO_DATA_FOUND)

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS, DEFENDER_ALERT_UPDATED_SUCCESSFULLY)

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

        return ret_val

    def initialize(self):
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        if not isinstance(self._state, dict):
            self.debug_print("Resetting the state file with the default format")
            self._state = {
                "app_version": self.get_app_json().get('app_version')
            }
            return self.set_status(phantom.APP_ERROR, DEFENDER_STATE_FILE_CORRUPT_ERROR)

        self._non_interactive = config.get('non_interactive', False)
        self._tenant = config[DEFENDER_CONFIG_TENANT_ID]
        self._client_id = config[DEFENDER_CONFIG_CLIENT_ID]
        self._client_secret = config[DEFENDER_CONFIG_CLIENT_SECRET]

        self._access_token = self._state.get(DEFENDER_TOKEN_STRING, {}).get(DEFENDER_ACCESS_TOKEN_STRING, None)
        if self._state.get(DEFENDER_STATE_IS_ENCRYPTED):
            try:
                if self._access_token:
                    self._access_token = self.decrypt_state(self._access_token, "access")
            except Exception as e:
                self.debug_print("{}: {}".format(DEFENDER_DECRYPTION_ERR, self._get_error_message_from_exception(e)))
                return self.set_status(phantom.APP_ERROR, DEFENDER_DECRYPTION_ERR)

        self._refresh_token = self._state.get(DEFENDER_TOKEN_STRING, {}).get(DEFENDER_REFRESH_TOKEN_STRING, None)
        if self._state.get(DEFENDER_STATE_IS_ENCRYPTED):
            try:
                if self._refresh_token:
                    self._refresh_token = self.decrypt_state(self._refresh_token, "refresh")
            except Exception as e:
                self.debug_print("{}: {}".format(DEFENDER_DECRYPTION_ERR, self._get_error_message_from_exception(e)))
                return self.set_status(phantom.APP_ERROR, DEFENDER_DECRYPTION_ERR)

        return phantom.APP_SUCCESS

    def finalize(self):
        try:
            if self._state.get(DEFENDER_TOKEN_STRING, {}).get(DEFENDER_ACCESS_TOKEN_STRING):
                self._state[DEFENDER_TOKEN_STRING][DEFENDER_ACCESS_TOKEN_STRING] = self.encrypt_state(self._access_token, "access")
        except Exception as e:
            self.debug_print("{}: {}".format(DEFENDER_ENCRYPTION_ERR, self._get_error_message_from_exception(e)))
            return self.set_status(phantom.APP_ERROR, DEFENDER_ENCRYPTION_ERR)

        try:
            if self._state.get(DEFENDER_TOKEN_STRING, {}).get(DEFENDER_REFRESH_TOKEN_STRING):
                self._state[DEFENDER_TOKEN_STRING][DEFENDER_REFRESH_TOKEN_STRING] = self.encrypt_state(self._refresh_token, "refresh")
        except Exception as e:
            self.debug_print("{}: {}".format(DEFENDER_ENCRYPTION_ERR, self._get_error_message_from_exception(e)))
            return self.set_status(phantom.APP_ERROR, DEFENDER_ENCRYPTION_ERR)

        if not self._state.get(DEFENDER_STATE_IS_ENCRYPTED):
            try:
                if self._state.get('code'):
                    self._state['code'] = self.encrypt_state(self._state['code'], "code")
            except Exception as e:
                self.debug_print("{}: {}".format(DEFENDER_ENCRYPTION_ERR, self._get_error_message_from_exception(e)))
                return self.set_status(phantom.APP_ERROR, DEFENDER_ENCRYPTION_ERR)
            if self._state.get(DEFENDER_TOKEN_STRING, {}).get(DEFENDER_ID_TOKEN_STRING):
                self._state[DEFENDER_TOKEN_STRING].pop(DEFENDER_ID_TOKEN_STRING)

        # Save the state, this data is saved across actions and app upgrades
        self._state[DEFENDER_STATE_IS_ENCRYPTED] = True
        self.save_state(self._state)
        _save_app_state(self._state, self.get_asset_id(), self)
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
