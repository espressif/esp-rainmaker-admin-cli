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


import getpass
import json
import sys
import os
import socket
from rmaker_admin_lib.logger import log
from rmaker_admin_lib import configmanager
from rmaker_admin_lib.exceptions import SSLError,\
    NetworkError,\
    RequestTimeoutError
try:
    import requests
    from requests.exceptions import RequestException
except ImportError as err:
    log.error('{}\nPlease run `pip install -r requirements.txt`'
              '\n'.format(err))
    sys.exit(1)
try:
    if os.path.exists(configmanager.SERVER_CONFIG_FILE):
        from rmaker_admin_lib import serverconfig, constants
except Exception as e:
    log.debug("Import serverconfig failed")
    sys.exit(1)


class User:
    """
    User class used to instantiate instances of user to perform various
    user login operations.

    :param email_id: Email-Id of User
    :type email_id: str
    """
    def __init__(self, email_id):
        """
        Instantiate user with email_id.
        """
        self.__email = email_id
        self.request_header = {'content-type': 'application/json'}
        log.debug('Login setup - email: {} '
                  'request_header: {}'.format(
                      self.__email,
                      self.request_header))

    def login(self, password=None):
        """
        Login to user with given password

        :param password: Password of User
        :type password: str
        """
        try:
            backslash = '/'
            socket.setdefaulttimeout(10)
            expected_resp = ["idtoken", "accesstoken", "refreshtoken"]
            # Get password from user
            if password is None:
                log.debug("Get password from user")
                password = getpass.getpass("Password:")
            log.debug("Password received")

            # Set HTTP Request
            path = 'login/'
            login_info = {
                'user_name': self.__email,
                'password': password
            }

            login_url = constants.HOST.rstrip(backslash) + backslash + path

            log.debug('Sending HTTP POST Request - login url:{} '
                      'request body: {}'.format(
                          login_url,
                          json.dumps(login_info)))

            # Send HTTP POST Request
            log.debug('Sending HTTP {} request - url: {} data: {} '
                      'headers: {}'.format(
                          'post',
                          login_url,
                          json.dumps(login_info),
                          self.request_header))

            response = requests.post(url=login_url,
                                     data=json.dumps(login_info),
                                     headers=self.request_header,
                                     verify=configmanager.CERT_FILE,
                                     timeout=(5.0, 5.0))

            response = json.loads(response.text)

            log.debug("Response received: {}".format(response))

            # Check response
            if 'status' in response:
                log.debug("Response status: {}".format(response['status']))
                if 'success' in response['status']:
                    for item in expected_resp:
                        if item not in response:
                            log.error('Expected response {} not found in '
                                      'response: {}'.format(item, response))
                            return False
                        else:
                            log.debug('Expected response {} received in '
                                      'response: {}'.format(item, response))

                    return response
                elif 'failure' in response['status']:
                    log.info(response['description'])
                    return False
                else:
                    log.debug("Login API HTTP status not in success/failure. Response received: {}".format(response))
                    return False

        except SSLError as ssl_err:
            log.error(ssl_err)
        except NetworkError as net_err:
            log.error(net_err)
        except RequestTimeoutError as req_err:
            log.error(req_err)
        except RequestException as req_exc_err:
            log.error(req_exc_err)
        except Exception as err:
            log.error(err)

    def get_new_token(self, refresh_token):
        """
        Get new token for User Login

        :param refresh_token: Refresh Token of User
        :type refresh_token: str
        """
        try:
            backslash = '/'
            socket.setdefaulttimeout(10)
            log.debug("Extending user login session")

            # Set HTTP Request
            path = 'login'
            request_payload = {
                'user_name':  self.__email,
                'refreshtoken': refresh_token
            }

            request_url = constants.HOST.rstrip(backslash) + backslash + path
            log.debug('Sending HTTP POST Request - request url: {} '
                      'request body: {}'.format(
                          request_url,
                          json.dumps(request_payload)))

            # Send HTTP POST Request
            log.debug('Sending HTTP {} request - url: {} data: {} '
                      'headers: {}'.format(
                          'post',
                          request_url,
                          json.dumps(request_payload),
                          self.request_header))

            response = requests.post(url=request_url,
                                     data=json.dumps(request_payload),
                                     headers=self.request_header,
                                     verify=configmanager.CERT_FILE,
                                     timeout=(5.0, 5.0))
            response = json.loads(response.text)

            log.debug("Response received: {}".format(response))

            # Check response
            if 'accesstoken' in response and 'idtoken' in response:
                log.debug("User session extended successfully")
                return response['accesstoken'], response['idtoken']
            return False, False

        except SSLError as ssl_err:
            log.error(ssl_err)
        except NetworkError as net_err:
            log.error(net_err)
        except RequestTimeoutError as req_err:
            log.error(req_err)
        except RequestException as req_exc_err:
            log.error(req_exc_err)
        except Exception as err:
            raise Exception(err)
