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

from __future__ import unicode_literals
from io import open
import os
import sys
import json
from rmaker_admin_lib.exceptions import FileError
from rmaker_admin_lib.logger import log

try:
    from builtins import input, str
except ImportError as err:
    log.error("{}\nPlease run `pip install -r requirements.txt`\n".format(err))
    sys.exit(1)

PATH_SEP = os.sep
CURR_DIR = os.path.dirname(__file__)
CERT_FILE = CURR_DIR + '{}..{}server_cert{}server_cert.pem'.format(PATH_SEP, PATH_SEP, PATH_SEP)

HOME_DIRECTORY = os.path.expanduser('~')
CONFIG_DIRECTORY = HOME_DIRECTORY + '{}.espressif{}rainmaker'.format(PATH_SEP, PATH_SEP)
CONFIG_FILE = CONFIG_DIRECTORY + '{}rainmaker_admin_config.json'.format(PATH_SEP)

SERVER_CONFIG_FILE = os.path.join(CURR_DIR, 'serverconfig.py')


class Config():
    def __init__(self, config=""):
        if config == "server":
            self.config_file = SERVER_CONFIG_FILE
        else:
            self.config_file = CONFIG_FILE
        log.debug("Config file set: {}".format(self.config_file))

    def read_config(self):
        '''
        Read from saved config file
        '''
        try:
            log.debug("Read from config file: {}".format(self.config_file))
            if not os.path.exists(self.config_file):
                log.debug('File not found: {}'.format(self.config_file))
                return None

            with open(self.config_file, "r") as config_file:
                user_config_data = json.load(config_file)

            log.debug("Config data received: {}".format(user_config_data))

            return user_config_data

        except Exception as err:
            log.error(FileError('Error occurred while reading config '
                                'from file {}\n{}'.format(
                                    self.config_file,
                                    err)))
            raise

    def remove_curr_login_config(self, email=""):
        '''
        Remove current login config from file

        :param email: Email-id of current user
        :type email: str
        '''
        log.debug("Removing current login config data from file: {}".format(
            self.config_file))
        while True:
            user_input = input('\nThis will end your current session for {}. '
                               'Do you want to continue (Y/N)? :'.format(
                                   email))
            if user_input not in ["Y", "y", "N", "n"]:
                log.info("Please provide Y/N only")
                continue
            elif user_input in ["N", "n"]:
                return False
            else:
                break
        try:
            os.remove(self.config_file)
            log.debug("Current login config removed from file: {}".format(
                self.config_file))
            return True
        except Exception as e:
            log.debug('Error: {}. Failed to remove current login config '
                      'from path {}'.format(
                          e, self.config_file))
            raise Exception('Error: Failed to remove current login '
                            'config from path {}'.format(self.config_file))

    def _set_login_config_data(self, data):
        '''
        Set login config data

        :param data: Login data to be set
        :type data: dict
        '''
        try:
            log.debug("Setting login config data")
            config_data = {}
            config_data['idtoken'] = data['idtoken']
            config_data['accesstoken'] = data['accesstoken']
            config_data['refreshtoken'] = data['refreshtoken']
            log.debug("Login config data set: {}".format(config_data))
            return config_data
        except KeyError as key_err:
            log.error("Key Error in login config data: {}".format(key_err))

    def save_config(self, data):
        '''
        Save login config data to file

        :param data: Login data to be set
        :type data: dict
        '''
        try:
            log.debug("Saving login config data")
            if not os.path.isdir(CONFIG_DIRECTORY):
                log.info('Config directory does not exist, '
                         'creating new directory : {}'.format(
                             CONFIG_DIRECTORY))
                os.makedirs(CONFIG_DIRECTORY)

            login_cfg_data = self._set_login_config_data(data)
            if not login_cfg_data:
                return False, False

            with open(self.config_file, 'w+', encoding='utf-8') as cfg_file:
                cfg_file.write(str(json.dumps(login_cfg_data)))

            return True, self.config_file

        except Exception as save_config_err:
            log.error(save_config_err)
            return False, False

    def update_config(self, data):
        '''
        Update current config data

        :param data: Config data to be updated
        :type data: dict
        '''
        try:
            if not os.path.exists(self.config_file):
                log.error('Update config failed. Config file {} '
                          'does not exist.'.format(self.config_file))
                return False

            with open(self.config_file, 'w', encoding='utf-8') as cfg_file:
                cfg_file.write(str(json.dumps(data)))

            return True

        except Exception as save_config_err:
            log.error(save_config_err)
            raise

    def set_server_config(self, endpoint):
        '''
        Set server config endpoint

        :param data: Server config endpoint to be used
        :type data: str
        '''
        try:
            backslash = '/'
            endpoint_to_write = "BASE_URL = '{}{}'".format(endpoint.rstrip(backslash), backslash)

            with open(self.config_file, 'w', encoding='utf-8') as cfg_file:
                cfg_file.write(endpoint_to_write)
                cfg_file.write('\n')

            return True

        except Exception as save_config_err:
            log.error(save_config_err)
            raise
