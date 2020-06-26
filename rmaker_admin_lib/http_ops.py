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

from io import open
import time
import sys
from rmaker_admin_lib.exceptions import SSLError, NetworkError
from rmaker_admin_lib.logger import log
try:
    import requests
    from requests.exceptions import ConnectionError, RequestException
except ImportError as err:
    log.error("{}\nPlease run `pip install -r requirements.txt`\n".format(err))
    sys.exit(1)

MAX_HTTP_CONNECTION_RETRIES = 5


def download_from_url(request_url):
    '''
    Download file from url

    :param request_url: Request URL to download file from
    :type request_url: str
    '''
    try:
        response = None
        while True:
            try:
                log.debug("Downloading file from url: {}".format(request_url))
                response = requests.get(url=request_url)
                response.raise_for_status()
            except requests.exceptions.SSLError:
                raise(SSLError())
            except (ConnectionError):
                log.error(NetworkError())
            except RequestException as err:
                log.error(err)

            if response:
                log.info("Node ids file downloaded successfully")
                log.debug("Response content: {}".format(response.content))
                return response.content
            else:
                log.info("Retrying...")
                time.sleep(5)

    except Exception as err:
        raise Exception(err)


def upload_cert(upload_url, filename):
    '''
    Upload Certificate file to AWS S3 Bucket

    :param upload_url: URL to upload file to
    :type upload_url: str

    :param filename: Name of file to upload
    :type filename: str
    '''
    try:
        response = None

        log.info("Uploading certificate file: {}".format(filename))
        while True:
            try:
                headers = {'Content-type': 'application/octet-stream'}
                log.debug("Upload Certificate - url: {} filename: {}".format(
                    upload_url,
                    filename))
                with open(filename, "rb") as f:
                    response = requests.put(url=upload_url,
                                            data=f,
                                            headers=headers)
                    response.raise_for_status()

            except requests.exceptions.SSLError:
                raise(SSLError())
            except (ConnectionError):
                log.error(NetworkError())
            except RequestException as req_exc_err:
                log.error(req_exc_err)

            if response:
                log.debug("Response received: {}".format(response))
                if response.status_code != 200:
                    break
                return True
            else:
                log.info("Retrying...")
                time.sleep(5)

    except Exception as err:
        raise Exception(err)
