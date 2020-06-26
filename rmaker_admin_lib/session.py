# Copyright 2020 Espressif Systems (Shanghai) PTE LTD
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

import time
import json
import os
import sys
import base64
import socket
from rmaker_admin_lib import configmanager
from rmaker_admin_lib.configmanager import Config
from rmaker_admin_lib.logger import log
from rmaker_admin_lib.user import User
from rmaker_admin_lib.exceptions import InvalidConfigError
from rmaker_admin_lib.exceptions import SSLError,\
    NetworkError,\
    RequestTimeoutError,\
    InvalidApiVersionError
try:
    import requests
    from requests.exceptions import RequestException
    from builtins import str
except ImportError as err:
    log.error("{}\nPlease run `pip install -r requirements.txt`\n".format(err))
    sys.exit(1)
try:
    if os.path.exists(configmanager.SERVER_CONFIG_FILE):
        from rmaker_admin_lib import serverconfig, constants
except Exception as e:
    log.debug("Import serverconfig failed")
    sys.exit(1)


class Session:
    '''
    Session for logged in user
    '''
    def __is_valid_version(self):
        '''
        Check if API version is valid
        '''
        backslash = '/'
        log.debug("Checking API Version")
        socket.setdefaulttimeout(10)
        path = 'apiversions'
        request_url = constants.HOST.split(
            constants.VERSION)[0].rstrip(backslash) + backslash + path
        log.debug('Sending GET HTTP Request - '
                  'request url: {}'.format(request_url))
        try:
            log.debug('Sending HTTP {} '
                      'request - url: {}'.format(
                          'get',
                          request_url))
            response = requests.get(url=request_url,
                                    verify=configmanager.CERT_FILE,
                                    timeout=(5.0, 5.0))
            response = json.loads(response.text)
            log.debug("Response received: {}".format(response))

            if 'supported_versions' in response:
                supported_versions = response['supported_versions']
                log.debug("Supported Versions: {}".format(supported_versions))
                if constants.VERSION in supported_versions:
                    log.debug("Version: {} supported".format(constants.VERSION))
                    return True

        except SSLError as ssl_err:
            log.error(ssl_err)
            return None
        except NetworkError as net_err:
            log.error(net_err)
            return None
        except RequestTimeoutError as req_err:
            log.error(req_err)
            return None
        except RequestException as req_exc_err:
            log.error(req_exc_err)
            return None
        except Exception as err:
            raise Exception(err)
        return False

    def get_token_attribute(self, attribute_name, token):
        '''
        Get User token attribute

        :param attribute_name: Token Attribute Name
        :type attribute_name: str

        :param token: User Token
        :type token: str
        '''
        log.debug("Getting token attribute")
        token_payload = token.split('.')[1]
        if len(token_payload) % 4:
            token_payload += '=' * (4 - len(token_payload) % 4)
        log.debug("Token Payload: {}".format(token_payload))
        try:
            str_token_payload = base64.b64decode(token_payload).decode("utf-8")
            log.debug("Token Playload String: {}".format(str_token_payload))
            attribute_value = json.loads(str_token_payload)[attribute_name]
            log.debug("Attribute Value: {}".format(attribute_value))
            if attribute_value is None:
                log.error(InvalidConfigError())
            return attribute_value
        except Exception as err:
            raise Exception(err)

    def __is_valid_token(self, token):
        '''
        Check is token is valid

        :param token: User Token
        :type token: str
        '''
        log.debug("Checking for session timeout")
        exp_timestamp = self.get_token_attribute('exp', token)
        log.debug("Expiry Timestamp: {}".format(exp_timestamp))
        current_timestamp = int(time.time())
        log.debug("Current Timestamp: {}".format(current_timestamp))
        if exp_timestamp > current_timestamp:
            log.debug("Session not expired")
            return True
        log.debug("Session expired")
        return False

    def get_access_token(self):
        '''
        Get Access Token
        '''
        try:
            log.debug("Getting access token")
            config = Config()
            config_data = config.read_config()
            if not config_data:
                log.info("User is not logged in. Please login to continue")
                log.debug('User config data not found. '
                          'Please login to continue')
                return False
            log.debug("Config data: {}".format(config_data))
            if 'accesstoken' not in config_data:
                log.error('Access Token not found in current login '
                          'config data from '
                          'file: {}'.format(config.config_file))
                return False
            access_token = config_data['accesstoken']
            if not self.__is_valid_token(access_token):
                log.info('Previous Session expired. Initialising new session')
                id_token = config_data['idtoken']
                email_id = self.get_token_attribute('email', id_token)
                log.debug("Email Id: {}".format(email_id))
                if not email_id:
                    log.debug("Failed to get email attribute from payload.")
                    return False
                valid_ver_status = self.__is_valid_version()
                if valid_ver_status is False:
                    log.error(InvalidApiVersionError())
                    return False
                elif valid_ver_status is None:
                    return False
                refresh_token = config_data['refreshtoken']
                user = User(email_id)
                access_token, id_token = user.get_new_token(refresh_token)
                log.debug('New config data received - access token: {} '
                          'id token: {}'.format(access_token, id_token))
                if not access_token and not id_token:
                    log.debug("Error getting new user token")
                    log.info("Previous Session expired. Cannot extend session. Please login to continue")
                    return False
                new_config = {}
                key_text = str('accesstoken')
                new_config[key_text] = access_token
                key_text = str('idtoken')
                new_config[key_text] = id_token
                key_text = str('refreshtoken')
                new_config[key_text] = refresh_token
                log.debug("New config data: {}".format(new_config))
                ret_status = config.update_config(new_config)
                log.debug("Config data update status: {}".format(ret_status))
                if not ret_status:
                    log.debug("Failed to update config.")
                    return False
                log.debug('Previous Session expired. New session initialised.')
            log.debug("Current Session is valid")
            return access_token
        except Exception as err:
            log.debug("Error while getting access token")
            return False

    def get_curr_user_creds(self, email=None):
        '''
        Get Current Logged In User Credentials

        :param email: Attribute to get
        :type email: str
        '''
        try:
            config = Config()
            config_data = config.read_config()
            if not config_data:
                return None
            id_token = config_data['idtoken']
            email_id = self.get_token_attribute('email', id_token)
            if not email_id:
                return None
            return email_id
        except Exception as err:
            log.debug('Error: {}. Failed to get '
                      'current user creds from config file'.format(err))
            raise Exception('Error: Failed to get '
                            'current user creds from config file'.format(err))
