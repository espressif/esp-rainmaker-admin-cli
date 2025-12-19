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

# Import the new ProfileManager
from rmaker_admin_lib.profile_manager import ProfileManager

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
    def __init__(self, config="", profile_override=None):
        """
        Initialize Config with ProfileManager integration.

        :param config: Config type - "server" for server config, otherwise for login config
        :param profile_override: Optional profile name to use instead of current profile.
        """
        if config == "server":
            self.config_file = SERVER_CONFIG_FILE
            self.profile_manager = None  # Server config doesn't use profiles
        else:
            self.config_file = CONFIG_FILE
            self.profile_manager = ProfileManager()
            self.profile_override = profile_override

            if profile_override:
                # Validate that the override profile exists
                if not self.profile_manager.profile_exists(profile_override):
                    raise ValueError(f"Profile '{profile_override}' does not exist")
                self.current_profile = profile_override
            else:
                self.current_profile = self.profile_manager.get_current_profile()
                # If no current profile, use default (will be created if needed)
                if self.current_profile is None:
                    self.current_profile = ProfileManager.DEFAULT_PROFILE_NAME

        log.debug("Config file set: {}".format(self.config_file))
        if self.profile_manager:
            log.debug("Current profile: {}".format(self.current_profile))

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

            from rmaker_admin_lib.logger import _mask_sensitive_payload
            log.debug("Config data received: {}".format(_mask_sensitive_payload(user_config_data)))

            return user_config_data

        except Exception as err:
            log.error(FileError('Error occurred while reading config '
                                'from file {}\n{}'.format(
                                    self.config_file,
                                    err)))
            raise

    def remove_curr_login_config(self, email=""):
        '''
        Remove current login config from file - now profile-aware

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
            # Use profile-based token storage if available
            if self.profile_manager and self.current_profile:
                self.profile_manager.clear_profile_tokens(self.current_profile)
                log.debug("Current login config removed for profile: {}".format(
                    self.current_profile))
            else:
                # Fall back to legacy file removal
                if os.path.exists(self.config_file):
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
            from rmaker_admin_lib.logger import _mask_sensitive_payload
            log.debug("Login config data set: {}".format(_mask_sensitive_payload(config_data)))
            return config_data
        except KeyError as key_err:
            log.error("Key Error in login config data: {}".format(key_err))

    def save_config(self, data):
        '''
        Save login config data to file - now profile-aware

        :param data: Login data to be set
        :type data: dict
        '''
        try:
            log.debug("Saving login config data")

            login_cfg_data = self._set_login_config_data(data)
            if not login_cfg_data:
                return False, False

            # Use profile-based token storage if available
            if self.profile_manager and self.current_profile:
                # Ensure profile exists (create default if needed)
                if not self.profile_manager.profile_exists(self.current_profile):
                    # Create default profile if it doesn't exist
                    log.info(f"Creating default profile '{self.current_profile}'")
                    self.profile_manager.create_custom_profile(
                        self.current_profile,
                        '',  # Base URL will be set separately
                        'Default profile'
                    )
                    # Set current profile
                    self.profile_manager.set_current_profile(self.current_profile)

                # Save tokens to profile
                self.profile_manager.set_profile_tokens(
                    self.current_profile,
                    idtoken=login_cfg_data.get('idtoken'),
                    refreshtoken=login_cfg_data.get('refreshtoken'),
                    accesstoken=login_cfg_data.get('accesstoken')
                )

                log.debug("Saved login config for profile: {}".format(self.current_profile))
                # Return the profile config file path instead of legacy file
                profile_config_file = self.profile_manager._get_profile_config_file(self.current_profile)
                return True, profile_config_file
            else:
                # Fall back to legacy file storage
                if not os.path.isdir(CONFIG_DIRECTORY):
                    log.info('Config directory does not exist, '
                             'creating new directory : {}'.format(
                                 CONFIG_DIRECTORY))
                    os.makedirs(CONFIG_DIRECTORY)

                with open(self.config_file, 'w+', encoding='utf-8') as cfg_file:
                    cfg_file.write(str(json.dumps(login_cfg_data)))

                return True, self.config_file

        except Exception as save_config_err:
            log.error(save_config_err)
            return False, False

    def update_config(self, data):
        '''
        Update current config data - now profile-aware

        :param data: Config data to be updated
        :type data: dict
        '''
        try:
            # Use profile-based token storage if available
            if self.profile_manager and self.current_profile:
                # Update tokens in profile
                self.profile_manager.set_profile_tokens(
                    self.current_profile,
                    idtoken=data.get('idtoken'),
                    refreshtoken=data.get('refreshtoken'),
                    accesstoken=data.get('accesstoken')
                )
                log.debug("Updated config for profile: {}".format(self.current_profile))
                return True
            else:
                # Fall back to legacy file storage (for non-profile operations)
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

    def set_server_config(self, endpoint, profile_name=None):
        '''
        Set server config endpoint - now profile-aware

        :param endpoint: Server config endpoint to be used
        :type endpoint: str
        :param profile_name: Optional profile name to use (defaults to 'default')
        :type profile_name: str
        '''
        try:
            # Initialize profile manager for server config operations
            profile_manager = ProfileManager()

            # Use provided profile name or default
            if profile_name is None:
                profile_name = ProfileManager.DEFAULT_PROFILE_NAME

            # Check if profile already exists
            if profile_manager.profile_exists(profile_name):
                # Warn user and ask if they want to override or create new
                print(f"\nProfile '{profile_name}' already exists.")
                print("Options:")
                print("  1. Override existing profile (will update base URL)")
                print("  2. Create a new profile with a different name")
                print("  3. Cancel")

                while True:
                    choice = input("Enter your choice (1/2/3): ").strip()
                    if choice == '1':
                        # Override existing profile
                        break
                    elif choice == '2':
                        # Create new profile
                        while True:
                            new_profile_name = input("Enter new profile name: ").strip()
                            if not new_profile_name:
                                print("Profile name cannot be empty. Please try again.")
                                continue
                            try:
                                profile_manager._validate_profile_name(new_profile_name)
                                if profile_manager.profile_exists(new_profile_name):
                                    print(f"Profile '{new_profile_name}' already exists. Please choose a different name.")
                                    continue
                                profile_name = new_profile_name
                                break
                            except ValueError as e:
                                print(f"Invalid profile name: {e}")
                                continue
                        break
                    elif choice == '3':
                        log.info("Server configuration cancelled.")
                        return False
                    else:
                        print("Invalid choice. Please enter 1, 2, or 3.")
                        continue

            # Ensure base_url ends with /
            backslash = '/'
            endpoint = endpoint.rstrip(backslash) + backslash

            # Create or update profile
            if profile_manager.profile_exists(profile_name):
                # Update existing profile
                profiles_config = profile_manager._load_profiles_config()
                if profile_name in profiles_config['custom_profiles']:
                    profiles_config['custom_profiles'][profile_name]['base_url'] = endpoint
                    profile_manager._save_profiles_config(profiles_config)
                    log.info(f"Updated profile '{profile_name}' with base URL '{endpoint}'")
            else:
                # Create new profile
                profile_manager.create_custom_profile(
                    profile_name,
                    endpoint,
                    f'Profile: {profile_name}'
                )
                log.info(f"Created profile '{profile_name}' with base URL '{endpoint}'")

            # Set as current profile
            profile_manager.set_current_profile(profile_name)

            # Also save to legacy serverconfig.py for backward compatibility
            endpoint_to_write = "BASE_URL = '{}'".format(endpoint)
            with open(self.config_file, 'w', encoding='utf-8') as cfg_file:
                cfg_file.write(endpoint_to_write)
                cfg_file.write('\n')

            log.info(f"Server configuration saved to profile '{profile_name}'")
            return True

        except Exception as save_config_err:
            log.error(save_config_err)
            raise

    def get_current_profile_name(self):
        """Get the name of the currently active profile."""
        if self.profile_manager:
            return self.current_profile
        return None

    def get_profile_base_url(self, profile_name=None):
        """Get base URL for a profile."""
        if not self.profile_manager:
            return None

        if profile_name is None:
            profile_name = self.current_profile

        if not profile_name:
            return None

        try:
            profile_config = self.profile_manager.get_profile_config(profile_name)
            return profile_config.get('base_url')
        except Exception:
            return None
