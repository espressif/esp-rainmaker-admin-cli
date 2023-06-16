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


import json
import re
import time
import sys
import datetime
from rmaker_admin_lib import configmanager
from rmaker_admin_lib.exceptions import SSLError,\
    NetworkError,\
    RequestTimeoutError,\
    InvalidJSONError
from rmaker_admin_lib.logger import log
try:
    import requests
    from requests.exceptions import RequestException
except ImportError as err:
    log.error('{}\nPlease run `pip install -r '
              'requirements.txt`\n'.format(err))
    sys.exit(1)

from rmaker_admin_lib import constants

MAX_HTTP_CONNECTION_RETRIES = 5
TAG_REGEX = "^ *[a-zA-Z_.0-9]+ *: *[a-zA-Z_.0-9]+ *$"
COLON = ":"
EMPTY_STRING = ""
COMMA = ","

class Node_Mfg:
    """
    Node_Mfg class used to instantiate instances to perform various
    node manufacturing operations.

    :param token: User token
    :type token: str
    """
    def __init__(self, token):
        """
        Instantiate node_mfg with user token (session)
        """
        self.request_header = {'content-type': 'application/json',
                               'Authorization': token}
        log.debug("Node Mfg request header: {}".format(self.request_header))

    def get_node_id_req(self, node_cnt, expected_resp=None):
        '''
        Request to get list of node ids

        :param node_cnt: Number of node ids to get
        :type node_cnt: int

        :param expected_resp: Data expected to be present in response
        :type expected_resp: str
        '''
        try:
            backslash = '/'
            retry_cnt = MAX_HTTP_CONNECTION_RETRIES
            log.debug("Retry count set to: {}".format(retry_cnt))
            err_status_key = "status"
            err_description_key = "description"

            path = 'admin/node_ids'
            request_url = constants.HOST.rstrip(backslash) + backslash + path
            request_body = {
                'node_count': node_cnt
            }
            log.debug('Request parameters set: request_url: {} '
                      'request_body: {}'.format(
                          request_url,
                          request_body))

            while retry_cnt > 0:
                try:
                    log.debug("Retry Count: {}".format(retry_cnt))
                    # Send HTTP POST Request
                    log.debug('Sending HTTP {} request - url: {} data: {} '
                              'headers: {}'.format(
                                  'post',
                                  request_url,
                                  json.dumps(request_body),
                                  self.request_header))
                    response = requests.post(url=request_url,
                                             data=json.dumps(request_body),
                                             headers=self.request_header,
                                             verify=configmanager.CERT_FILE,
                                             timeout=(5.0, 5.0))
                    log.debug('Response status code '
                              'received: {}'.format(response.status_code))
                    response = json.loads(response.text)
                    log.debug("HTTP Response received: {}".format(response))

                    if expected_resp in response:
                        log.debug('Expected response {} exists '
                                  'in response'.format(expected_resp))
                        return response[expected_resp]
                    elif err_status_key in response:
                        log.debug('Request failed: '
                                  'response received: {}'.format(response))
                        log.error("Status: {} \n{}".format(
                            response[err_status_key],
                            response[err_description_key]))
                        return None
                except NetworkError as net_err:
                    log.info(net_err)
                except RequestTimeoutError as req_err:
                    log.info(req_err)

                log.info('Retrying...No of retries left: {}'.format(
                    str(retry_cnt - 1))
                )
                retry_cnt -= 1
                time.sleep(5)
            return None
        except SSLError as ssl_err:
            log.error(ssl_err)
        except Exception as err:
            raise Exception(err)

    def gen_node_id(self, node_count):
        '''
        Generate list of node ids

        :param node_cnt: Number of node ids to get
        :type node_cnt: int
        '''
        try:
            backslash = '/'
            req_id = None
            log.info("Sending request for generating node ids: {}".format(
                node_count)
            )
            expected_resp = 'request_id'
            log.debug('Sending request for node ids for number of nodes: {}. '
                      'Expected response: {}'.format(
                          node_count,
                          expected_resp))
            req_id = self.get_node_id_req(
                node_count,
                expected_resp=expected_resp)
            if not req_id:
                log.debug("Expected response: {} not found.".format(
                    expected_resp))
                return False
            log.info('Request for generating '
                     'node ids: {} is successful'.format(node_count))

            retry_cnt = MAX_HTTP_CONNECTION_RETRIES
            expected_key_in_resp = "url"

            path = 'admin/node_ids'
            query_params = {'request_id': req_id}
            request_url = constants.HOST.rstrip(backslash) + backslash + path

            log.debug('Sending GET HTTP Request - request url: {} '
                      'query params: {}'.format(request_url, query_params))

            log.info('Sending request for getting {} '
                     'for node ids file'.format(expected_key_in_resp))

            while retry_cnt > 0:
                try:
                    log.debug('Sending HTTP {} request - url: {} params: {} '
                              'headers: {}'.format(
                                  'get',
                                  request_url,
                                  query_params,
                                  self.request_header))
                    # Send query params in HTTP GET Request
                    response = requests.get(url=request_url,
                                            params=query_params,
                                            headers=self.request_header,
                                            verify=configmanager.CERT_FILE,
                                            timeout=(5.0, 5.0))
                    log.debug("Response status code received: {}".format(
                        response.status_code))
                    response = json.loads(response.text)
                    log.debug("Response received: {}".format(response))

                    curr_time = time.time()
                    timestamp = datetime.datetime.fromtimestamp(
                        curr_time).strftime('%H:%M:%S')
                    log.info("[{:<6}] Current status: {:<3}".format(
                        timestamp,
                        response['status']))
                    if 'success' in response['status']:
                        log.debug("Response status: {}".format(
                            response['status']))
                        if expected_key_in_resp not in response:
                            raise InvalidJSONError
                        log.info("Node ids file url received successfully")
                        log.debug("URL received: {}".format(
                            response[expected_key_in_resp]))
                        return response[expected_key_in_resp]
                    elif 'in_progress' in response['status']:
                        time.sleep(5)
                        continue
                    elif 'failure' in response['status']:
                        log.debug('Request failed: response '
                                  'received: {}'.format(response))
                        log.error("Status: {} \n {}".format(
                            response['status'],
                            response['description']))
                        return None

                except NetworkError as net_err:
                    log.error(net_err)
                except RequestTimeoutError as req_err:
                    log.error(req_err)

                log.info('Retrying...No of retries left: {}'.format(
                    str(retry_cnt - 1)))
                retry_cnt -= 1
                time.sleep(5)

            return None

        except InvalidJSONError as json_err:
            log.error(json_err)
        except SSLError as ssl_err:
            log.error(ssl_err)
        except Exception as err:
            raise Exception(err)

    def get_cert_upload_url(self, cert_filename):
        '''
        Get URL to upload device certificates

        :param cert_filename: Filename having certifcates
        :type cert_filename: str
        '''
        try:
            backslash = '/'
            log.info("Get URL for uploading certificates file")
            retry_cnt = MAX_HTTP_CONNECTION_RETRIES
            expected_key_in_resp = "url"
            err_status_key = "status"

            path = 'admin/node_certificates/register'
            query_params = {'file_name': cert_filename}
            request_url = constants.HOST.rstrip(backslash) + backslash + path

            log.debug('Sending request to get URL '
                      'for uploading certificates file '
                      '- url: {} params: {}'.format(request_url, query_params))

            while retry_cnt > 0:
                try:
                    log.debug('Sending HTTP {} request - url: {} params: {} '
                              'headers: {}'.format(
                                  'get',
                                  request_url,
                                  query_params,
                                  self.request_header))
                    # Send query params in HTTP GET Request
                    response = requests.get(url=request_url,
                                            params=query_params,
                                            headers=self.request_header,
                                            verify=configmanager.CERT_FILE,
                                            timeout=(5.0, 5.0))
                    log.debug("Response status code received: {}".format(
                        response.status_code))
                    response = json.loads(response.text)
                    log.debug("Response received: {}".format(response))

                    if expected_key_in_resp in response:
                        log.debug('Expected key: {} present in '
                                  'response: {}'.format(
                                      expected_key_in_resp,
                                      response))
                        log.info('URL for uploading certificates file '
                                 'received successfully')
                        log.debug("URL received: {}".format(
                            response[expected_key_in_resp]))
                        return response[expected_key_in_resp]
                    elif err_status_key in response:
                        log.debug('Request failed: response '
                                  'received: {}'.format(response))
                        log.error("Status: {} \n {}".format(
                            response[err_status_key],
                            response['description']))
                        return None

                except NetworkError as net_err:
                    log.error(net_err)
                except RequestTimeoutError as req_err:
                    log.error(req_err)

                log.info('Retrying...No of retries '
                         'left: {}'.format(str(retry_cnt - 1)))
                retry_cnt -= 1
                time.sleep(5)

            return None

        except SSLError as ssl_err:
            log.error(ssl_err)
        except Exception as req_exc_err:
            raise Exception(req_exc_err)

    def validate_groupnames(self, group_name):
        '''
        API to validate the following things:
        The parent groupname whether it exists or not and return parent group ID if the group is level 0 group
        The groupname whether the it is level 0 group, if it exists

        :param group_name: Group name to be validated
        :type group_name: str
        return values:
        is_present: str 
        group_id: str
        '''
        try:
            backslash = '/'
            log.info("Validating Group Names")

            path = 'admin/node_group'
            query_params = {'group_name': group_name}
            request_url = constants.HOST.rstrip(backslash) + backslash + path
            log.debug("Get admin node group - url: {} params: {}".format(
                request_url,
                query_params))

            log.debug('Sending HTTP {} request - url: {} params: {} '
                      'headers: {}'.format(
                          'get',
                          request_url,
                          query_params,
                          self.request_header))
            # Send query params in HTTP GET Request
            response = requests.get(url=request_url,
                                    params=query_params,
                                    headers=self.request_header,
                                    verify=configmanager.CERT_FILE,
                                    timeout=(5.0, 5.0))

            log.debug("Response status code received: {}".format(
                response.status_code))
            response = json.loads(response.text)
            log.debug("Response received: {}".format(response))
            
            if "status" in response:
                if 'failure' in response['status']:
                    log.debug('Request failed: '
                         'Response received: {}'.format(response))
                    return False,""

            is_present = False
            parent_group_id = ""
            for group_response in response:
                is_present = True
                if "parent_group_id" in group_response:
                    continue
                elif "group_id" in group_response:
                    parent_group_id = group_response["group_id"]
            return is_present, parent_group_id
        except SSLError as ssl_err:
            log.error(ssl_err)
        except NetworkError as net_err:
            log.error(net_err)
        except RequestTimeoutError as req_err:
            log.error(req_err)
        except Exception as req_exc_err:
            raise Exception(req_exc_err)

    def validate_tags(self, tags):
        '''
        This function will validate the tags and return true and false accordingly.It also trims the whitespaces if any
        :param tags: The comma separated string of tags  
        :type tags: str
        return values:
        is_valid: bool
        tags: string
        '''
        try:
            log.info("Validating Tags")
            tags_array = tags.split(",")

            if len(tags_array)<1:
                return False, EMPTY_STRING

            for tag in tags_array:
                regexMatch = re.search(TAG_REGEX, tag)
                if regexMatch:
                    splitArray = tag.split(":")
                    if len(splitArray) == 2 :
                        tag = tag.strip(splitArray[0]) + ":" + tag.strip(splitArray[1])
                else:
                    return False, EMPTY_STRING
            
            return True, COMMA.join(tags_array)
        except Exception as exeption_validating_tags:
            log.error(exeption_validating_tags)

    def register_cert_req(self, filename, md5_checksum, refresh_token, node_type, model, group_name,parent_group_id,subtype,tags,
                          expected_resp='request_id'):
        '''
        Request to register device certificates

        :param filename: Filename of uploaded device certificates file
        :type filename: str

        :param md5_checksum: MD5 Checksum of file
        :type md5_checksum: str

        :param expected_resp: Data expected to be present in response
        :type expected_resp: str
        '''
        try:
            backslash = '/'
            log.debug("Sending request to register certificate")
            retry_cnt = MAX_HTTP_CONNECTION_RETRIES
            err_status_key = "status"

            path = 'admin/node_certificates/register'
            request_url = constants.HOST.rstrip(backslash) + backslash + path
            request_body = {
                'file_name': filename,
                'file_md5': md5_checksum,
                'refresh_token': refresh_token,
                'group_name': group_name,
                'type': node_type,
                'model': model,
                'parent_group_id':parent_group_id,
                'subtype':subtype,
                'tags':tags,
            }
            log.debug('Register Certificate Request - url: {} '
                      'req_body: {}'.format(request_url, request_body))

            while retry_cnt > 0:
                try:
                    # Send HTTP POST Request
                    log.debug('Sending HTTP {} request - url: {} data: {} '
                              'headers: {}'.format(
                                  'post',
                                  request_url,
                                  json.dumps(request_body),
                                  self.request_header))
                    response = requests.post(url=request_url,
                                             data=json.dumps(request_body),
                                             headers=self.request_header,
                                             verify=configmanager.CERT_FILE,
                                             timeout=(5.0, 5.0))
                    log.debug('Response status code received: {}'.format(
                        response.status_code))
                    response = json.loads(response.text)
                    log.debug("Response received: {}".format(response))

                    if 'status' in response:
                        log.debug("Response status: {}".format(
                            response['status']))
                        if 'success' in response['status']:
                            log.debug('Expected response {} '
                                      'received in response: {}'.format(
                                          expected_resp,
                                          response))
                            log.debug("Expected response: {}".format(
                                response[expected_resp]))
                            return response[expected_resp]
                        elif 'failure' in response['status']:
                            log.debug('Request failed: '
                                      'Response received: {}'.format(
                                          response))
                            log.error('Status: {} \n {}'.format(
                                response[err_status_key],
                                response['description']))
                            return False

                except NetworkError as net_err:
                    log.error(net_err)
                except RequestTimeoutError as req_err:
                    log.error(req_err)

                log.info("Current status: {}".format(response['status']))
                log.debug("Retrying...No of retries left: {}".format(
                    str(retry_cnt - 1)))
                retry_cnt -= 1
                time.sleep(5)

            return None

        except SSLError as ssl_err:
            log.error(ssl_err)
        except Exception as req_exc_err:
            raise Exception(req_exc_err)

    def get_register_cert_status(self, request_id):
        '''
        Register device certificates

        :param request_id: Request Id of device
                           certificate registration request
        :type request_id: str
        '''
        try:
            backslash = '/'
            log.info("Getting device certificate registration status")

            path = 'admin/node_certificates/register'
            query_params = {'request_id': request_id}
            request_url = constants.HOST.rstrip(backslash) + backslash + path
            log.debug("Register Certificate - url: {} params: {}".format(
                request_url,
                query_params))

            log.debug('Sending HTTP {} request - url: {} params: {} '
                      'headers: {}'.format(
                          'get',
                          request_url,
                          query_params,
                          self.request_header))
            # Send query params in HTTP GET Request
            response = requests.get(url=request_url,
                                    params=query_params,
                                    headers=self.request_header,
                                    verify=configmanager.CERT_FILE,
                                    timeout=(5.0, 5.0))
            log.debug("Response status code received: {}".format(
                response.status_code))
            response = json.loads(response.text)
            log.debug("Response received: {}".format(response))

            log.debug("Current status: {:<3}".format(response['status']))

            return response['status']

        except SSLError as ssl_err:
            log.error(ssl_err)
        except NetworkError as net_err:
            log.error(net_err)
        except RequestTimeoutError as req_err:
            log.error(req_err)
        except Exception as req_exc_err:
            raise Exception(req_exc_err)

    def get_mqtthostname(self,is_local):
        '''
        Get MQTT Hostname
        '''
        try:
            backslash = '/'
            log.info("Sending request to get mqtt endpoint")
            retry_cnt = MAX_HTTP_CONNECTION_RETRIES
            #If is_local is true or input node_ids.cs file is given, we get MQTT endpoint via unauthenticated API.
            if is_local:
                path = 'mqtt_host'
                host = constants.API_URL
            else:
                path = 'admin/mqtt_host'
                host = constants.HOST

            request_url = host.rstrip(backslash) + backslash + path
            log.debug("Get MQTT hostname - url: {}".format(request_url))

            while retry_cnt > 0:
                log.debug('Sending HTTP {} request - url: {} '
                          'headers: {}'.format(
                              'get',
                              request_url,
                              self.request_header))
                response = requests.get(url=request_url,
                                        headers=self.request_header,
                                        verify=configmanager.CERT_FILE,
                                        timeout=(5.0, 5.0))
                log.debug("Response status code received: {}".format(
                    response.status_code))
                response = json.loads(response.text)
                log.debug("Response received: {}".format(response))

                if 'mqtt_host' in response:
                    log.debug("Response mqtt hostname: {}".format(
                        response['mqtt_host']))
                    return response['mqtt_host']

                log.info("Retrying...No of retries left: {}".format(
                    str(retry_cnt - 1)))
                retry_cnt -= 1
                time.sleep(5)

            return False

        except SSLError as ssl_err:
            log.error(ssl_err)
        except NetworkError as net_err:
            log.error(net_err)
        except RequestTimeoutError as req_err:
            log.error(req_err)
        except RequestException as err:
            log.error(err)
        except Exception as req_exc_err:
            raise Exception(req_exc_err)
