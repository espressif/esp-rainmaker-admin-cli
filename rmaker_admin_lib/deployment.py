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
import sys

from rmaker_admin_lib import constants
from rmaker_admin_lib.exceptions import NetworkError, RequestTimeoutError
from rmaker_admin_lib.logger import log

try:
    import requests
    from requests.exceptions import RequestException
except ImportError as err:
    log.error("{}\nPlease run `pip install -r requirements.txt`\n".format(err))
    sys.exit(1)


def check_ses_status(token):
    """
    Check if the super admin's SES email is verified
    OR is deployment is in sandbox by calling the
    admin/rainmaker_deployment_details API endpoint.

    :param token: User access token
    :type token: str
    :return: True if SES is configured, False otherwise
    :rtype: bool
    """
    try:
        backslash = "/"
        log.debug("Checking SES status")

        # Set up request headers
        request_header = {"content-type": "application/json", "Authorization": token}

        # Set up request URL
        path = "admin/rainmaker_deployment_details"
        request_url = constants.HOST.rstrip(backslash) + backslash + path

        log.debug(
            "Sending HTTP GET request - url: {} headers: {}".format(
                request_url, request_header
            )
        )

        # Send HTTP GET Request
        response = requests.get(
            url=request_url,
            headers=request_header,
            params={"pre_requisite": True},
            timeout=(30.0, 30.0),
        )

        # Parse response
        response_data = json.loads(response.text)
        log.debug(f"SES status Response received: {response_data}")

        # Check if the response contains the required field
        if "pre_requisite_details" in response_data:
            pre_requisite_details = response_data["pre_requisite_details"]
            is_verified = pre_requisite_details.get(
                "is_super_admin_ses_verified", False
            ) or pre_requisite_details.get("is_ses_in_production", False)
            log.debug("SES status: {}".format(is_verified))
            return bool(is_verified)
        else:
            log.debug("SES status not found in response")
            return False

    except NetworkError as net_err:
        log.error(net_err)
        return False
    except RequestTimeoutError as req_err:
        log.error(req_err)
        return False
    except RequestException as req_exc_err:
        log.error(req_exc_err)
        return False
    except Exception as err:
        log.error("Error checking SES status: {}".format(err))
        return False
