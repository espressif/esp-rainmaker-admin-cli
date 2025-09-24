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
import os
import re
import shutil
import sys
import hashlib
import datetime
import traceback
import shortuuid
import csv
import distutils.dir_util
from rmaker_admin_lib.exceptions import FileError
from rmaker_admin_lib.node_mfg import Node_Mfg
from rmaker_admin_lib import configmanager
from rmaker_admin_lib.certs import *
from rmaker_admin_lib.certs import MQTT_ENDPOINT_FILENAME, MQTT_CRED_HOST_FILENAME, gen_hex_str
from rmaker_admin_lib.http_ops import download_from_url, upload_cert
from rmaker_admin_lib.logger import log
from rmaker_admin_lib.user import User
from rmaker_admin_lib.session import Session
from rmaker_admin_lib.configmanager import SERVER_CONFIG_FILE
from rmaker_admin_lib.csv_validator import CsvValidator
from rmaker_admin_lib.constants import MQTT_PREFIX_SUBFOLDER_REGEX
from rmaker_admin_lib.constants import BLUETOOTH
from rmaker_admin_lib.deployment import check_ses_status
try:
    from future.utils import iteritems
    from builtins import input, str
except ImportError as err:
    log.error("{}\nPlease run `pip install -r requirements.txt`\n".format(err))
    sys.exit(1)


# Static filenames for CA certificate and CA Private Key
CACERT_FILENAME = "ca.crt"
CA_KEY_FILENAME = "ca.key"
DIR_PREFIX = "Mfg"


def _create_date_dir(curr_outdir):
    '''
    Create date dir
    '''
    log.debug("Current outdir: {}".format(curr_outdir))
    date_dirname = datetime.datetime.now().strftime('%Y-%m-%d')
    outdir_path = os.path.join(curr_outdir, date_dirname)
    if not os.path.isdir(outdir_path):
        # Create new directory
        os.makedirs(outdir_path)
        log.debug("Directory created: {}".format(outdir_path))
    # New directory created is returned or existing one is returned
    return outdir_path

def _create_cnt_dir(curr_outdir):
    '''
    Create count dir
    '''
    log.debug("Current outdir: {}".format(curr_outdir))
    new_cnt = len(os.listdir(curr_outdir)) + 1
    max_dirname_len = 6
    zeros_prefix_len = max_dirname_len - len(str(new_cnt))
    zero_prefix_str = '0' * zeros_prefix_len
    # Get latest count of mfg directories created (if any)
    mfg_new_dir_str = DIR_PREFIX + "-" + zero_prefix_str + str(new_cnt)
    mfg_new_dirpath = os.path.join(curr_outdir, mfg_new_dir_str)
    if not os.path.isdir(mfg_new_dirpath):
        os.makedirs(mfg_new_dirpath)
        log.debug("Directory created: {}".format(mfg_new_dirpath))
    f= open(os.path.join(mfg_new_dirpath,".gitignore"),"w+")
    f.write("*")
    f.close()
    return mfg_new_dirpath

def _print_keyboard_interrupt_message():
    log.info("Press Ctrl-C to abort")

def _cli_arg_check(arg, expected_arg, err_msg=None):
    '''
    Check if arg is given as CLI input

    :param arg: Input argument provided
    :type arg: str

    :param expected_arg: Expected argument
    :type expected_arg: str

    :param err_msg: Error message
    :type err_msg: str

    :return: True on Success, False on Failure
    :rtype: bool
    '''
    if not arg:
        if err_msg:
            log.error("{}".format(err_msg))
        else:
            log.error("{} is required".format(expected_arg))
        return False
    return True

def _check_dir_exists(dirpath):
    log.debug("Check if dir exists: {}".format(dirpath))
    if os.path.isdir(dirpath):
        sys.exit("Directory {} exists. Please provide a different <outdir>".format(dirpath))

def _check_file_exists(filepath):
    log.debug("Check if file exists: {}".format(filepath))
    if os.path.exists(filepath):
        sys.exit("File {} exists. Please provide a different <outdir>".format(filepath))

def _get_cacert_user_input(cfg, cfg_menu):
    '''
    Get CA Certficate Data from User

    :param cfg: CA Certificate config
    :type cfg: dict

    :param cfg_menu: CA Certificate config menu
    :type cfg_menu: dict

    :return: Config data
    :rtype: dict
    '''
    # Get CA Certificate data input from user
    log.debug("Getting CA certificate config data from User")

    for (cfg_key, _) in iteritems(cfg):
        log.debug("Config Key: {}".format(cfg_key))
        while True:
            input_data = input(cfg_menu[cfg_key])
            log.debug("Input received from user: {}".format(input_data))
            if input_data:
                if cfg_key == "country_name" and not len(input_data) == 2:
                    print("Country name must be a 2 character country code")
                    continue
                cfg[cfg_key] = str(input_data)
                log.debug("Config: {} set for key: {}".format(
                    input_data,
                    cfg_key
                ))
            elif not input_data and cfg_key == "common_name":
                print("Common Name is mandatory")
                continue
            break
    log.debug("CA Certificate config data received from user")
    return cfg

def _set_output_dir(outdir):
    '''
    Set output dir
    '''
    path_sep = os.sep
    outdir = os.path.expanduser(outdir.rstrip(path_sep))
    log.debug("Initial Outdir: {}".format(outdir))
    # Create date dir
    outdir = _create_date_dir(outdir)
    log.debug("New outdir set to: {}".format(outdir))
    # Create mfg cnt dir
    outdir = _create_cnt_dir(outdir)
    log.debug("New outdir set to: {}".format(outdir))
    return outdir

def _set_output_dir_cacert(outdir, endpointprefix):
    """
    Set output directory for CA Certificates.

    This function ensures that a 'ca_certificates' directory exists in the
    provided `outdir` or current directory if no `outdir` is specified.
    Inside the 'ca_certificates' directory, it creates a subfolder named
    after the `endpointprefix`.

    :param outdir: The base directory where 'ca_certificates' should be created.
    :param endpointprefix: The unique prefix for the subdirectory inside 'ca_certificates'.
    :return: The path to the endpoint-specific directory inside 'ca_certificates'.
    """
    # Use current directory if outdir is not provided
    if not outdir:
        outdir = os.getcwd()

    # Remove any trailing slashes or path separators
    outdir = os.path.expanduser(outdir.rstrip(os.sep))
    log.debug("Initial outdir: {}".format(outdir))

    # Define 'ca_certificates' directory
    ca_certificates_dir = os.path.join(outdir, 'ca_certificates')

    # Create 'ca_certificates' directory if it doesn't exist
    if not os.path.exists(ca_certificates_dir):
        os.makedirs(ca_certificates_dir)
        log.debug("Directory created: {}".format(ca_certificates_dir))
    else:
        log.debug("'ca_certificates' directory already exists")

    # Create the endpoint-specific folder inside 'ca_certificates'
    endpoint_dir = os.path.join(ca_certificates_dir, endpointprefix)

    # Create the endpoint-specific directory if it doesn't exist
    if not os.path.exists(endpoint_dir):
        os.makedirs(endpoint_dir)
        log.debug("Directory created: {}".format(endpoint_dir))
    else:
        log.debug("Directory for endpoint '{}' already exists".format(endpointprefix))

    # Return the path to the endpoint-specific directory
    return endpoint_dir

def _gen_common_files_dir(outdir):
    '''
    Generate common files dir
    '''
    # Create output directory for all common files generated
    common_outdir = os.path.join(outdir, 'common')
    if not os.path.isdir(common_outdir):
        distutils.dir_util.mkpath(common_outdir)
        log.debug("Directory created: {}".format(common_outdir))
    return common_outdir

def generate_ca_cert(vars=None, outdir=None, common_outdir=None, cli_call=True, mqtt_endpoint=None):
    '''
    Generate CA Certificate

    :param vars: `outdir` as key - Output directory
                                   to save generated CA Certificate,
                                   defaults to current directory
    :type vars: str

    :raises Exception: If there is any exception
                       while generating CA Certificate
            KeyboardInterrupt: If there is a keyboard
                               interrupt by user

    :return: None on Failure
    :rtype: None
    '''
    try:
        # Get mqttendpoint to uniquely identify folder
        if mqtt_endpoint == None:
            node_mfg = Node_Mfg(None)
            is_local = True
            mqtt_endpoint = node_mfg.get_mqtthostname(is_local)
        # Normalize tuple return to a string host
        if isinstance(mqtt_endpoint, tuple):
            mqtt_endpoint = mqtt_endpoint[0]
        if not isinstance(mqtt_endpoint, str):
            mqtt_endpoint = ""

        # Extract the mqtt_endpoint prefix using regex
        ca_prefix = re.match(MQTT_PREFIX_SUBFOLDER_REGEX, mqtt_endpoint)
        if ca_prefix:
            endpointprefix = ca_prefix.group(1)
        else:
            endpointprefix = "default"

        log.debug("Generate CA certificate")

        cmd_flag_outdir = vars['outdir']
        cwd = os.getcwd()
        # Set output directory using endpoint prefix when ca cert generate command is run without any outdir
        if cmd_flag_outdir == cwd and not common_outdir and not outdir:
            outdir_cwd = _set_output_dir_cacert(vars['outdir'], endpointprefix)
        # Create a dir if does not exist when outdir is given in ca cert generate command to add cert & key without any sub-folders
        elif vars['outdir'] and not common_outdir:
            outdir_cwd = vars['outdir']
            os.makedirs(outdir_cwd, exist_ok=True)  # Ensures the directory is created if it doesn't exist
        # Set output directory using endpoint prefix when device cert generate command is run
        elif common_outdir:
            outdir_cwd = _set_output_dir_cacert(None, endpointprefix)


        ca_cert_filepath_original = os.path.join(outdir_cwd, CACERT_FILENAME)
        ca_key_filepath_original = os.path.join(outdir_cwd, CA_KEY_FILENAME)
        log.info("\nCA Key Filepath: {}".format(ca_key_filepath_original))

        # Create the common directory only if common_outdir is passed
        if common_outdir:
            common_outdir = _gen_common_files_dir(outdir)
            # Set CA cert and CA key filepaths within the common directory
            cacert_filepath_common = os.path.join(common_outdir, CACERT_FILENAME)
            cakey_filepath_common = os.path.join(common_outdir, CA_KEY_FILENAME)

        # Check if the CA certificate and key already exist
        if os.path.exists(ca_cert_filepath_original) and os.path.exists(ca_key_filepath_original):
            log.info("\nCA Certificate and Key already exist. Reusing the existing files.\n")

            # If an existing certificate and key are found, load them and return as objects
            existing_cert = load_existing_cert(ca_cert_filepath_original)  # Load as x509.Certificate object
            existing_key = load_existing_key(ca_key_filepath_original)  # Load as RSAPrivateKey object

            # If common_outdir is provided, copy the existing cert and key to the common_outdir
            if common_outdir:
                shutil.copy(ca_cert_filepath_original, cacert_filepath_common)
                shutil.copy(ca_key_filepath_original, cakey_filepath_common)
                log.info('CA Certificate and Key successfully added to both directories: {}\n and {}\n'.format(common_outdir, outdir_cwd))
            else:
                log.info('CA Certificate and Key already present in directory: {}\n'.format(outdir_cwd))

            # Return the existing cert and key
            return existing_cert, existing_key

        # If no existing files, ask the user if they want to create new ones
        create_new_cert = input("No CA certificate found. Do you want to create a new one? [Y/N]: ")
        if create_new_cert.lower() != 'y':
            log.info("CA Certificate generation aborted by user.")
            return

        # If CLI call, display the output directory
        if cli_call:
            _print_keyboard_interrupt_message()
            if common_outdir:
                log.info('Files generated will be stored in directory: {}\n and {}\n'.format(common_outdir, outdir_cwd))
            else:
                log.info('Files generated will be stored in directory: {}\n'.format(outdir_cwd))

        # Set CA cert input config menu
        cacert_cfg_menu = {
            "country_name": "Country Name (2 letter code) []:",
            "state_name": "State or Province Name (full name) []:",
            "locality_name": "Locality Name (eg, city) []:",
            "org_name": "Organization Name (eg, company) []:",
            "org_unit_name": "Organizational Unit Name (eg, section) []:",
            "common_name": "Common Name (eg, fully qualified host name) []:",
            "email_addr": "Email Address []:"
        }

        # Initialise CA cert config data
        ca_cert_cfg = {
            "country_name": "",
            "state_name": "",
            "locality_name": "",
            "org_name": "",
            "org_unit_name": "",
            "common_name": "",
            "email_addr": ""
        }
        print('\nPlease enter information which will be '
              'incorporated in your CA Certificate.\n'
              'To leave the field blank, press Enter.\n')

        # Get CA Certificate info from user
        ca_cert_cfg_values = _get_cacert_user_input(ca_cert_cfg, cacert_cfg_menu)

        # Generate CA Private Key
        ca_private_key = generate_private_key()
        if not ca_private_key:
            log.error("Failed to generate private key")
            return

        # Save CA Private Key into the respective directories
        ret_status_original = save_key(ca_private_key, ca_key_filepath_original)
        if common_outdir:
            # Also save in the common_outdir
            ret_status_common = save_key(ca_private_key, cakey_filepath_common)
            if not ret_status_original or not ret_status_common:
                return
        else:
            if not ret_status_original:
                return

        # Generate CA Certificate
        cacert = generate_cacert(ca_cert_cfg_values, ca_private_key)
        if not cacert:
            print("Failed to generate CA certificate")
            return

        # Save CA Certificate into the respective directories
        ret_status_original = save_cert(cacert, ca_cert_filepath_original)
        if common_outdir:
            # Also save in the common_outdir
            ret_status_common = save_cert(cacert, cacert_filepath_common)
            if not ret_status_original or not ret_status_common:
                return
        else:
            if not ret_status_original:
                return

        # Adjust log message based on whether common_outdir is used or not
        if common_outdir:
            log.info('CA Certificate generated successfully in both directories: {}\n and {}\n'.format(common_outdir, outdir_cwd))
        else:
            log.info('CA Certificate generated successfully in directory: {}\n'.format(outdir_cwd))

        # Output message based on CLI call
        if cli_call:
            log.info('You can now run: \npython rainmaker_admin_cli.py certs '
                     'devicecert generate -h '
                     '(Generate Device Certificate(s))')
        else:
            return cacert, ca_private_key

    except KeyboardInterrupt:
        log.error("\nCA Certificate Not Generated")
    except Exception as e:
        log.error("Error: {}".format(e))

def _get_and_save_ca_key_from_input(outdir, filepath):
    # Get CA Certificate Private Key from file
    ca_private_key = get_ca_key_from_file(filepath)
    if not ca_private_key:
        return
    log.debug("CA Key data recieved")
    # Save CA key if given as input
    ret_status = save_key(ca_private_key,
                          os.path.join(outdir, CA_KEY_FILENAME))
    if not ret_status:
        return
    log.debug("CA Key saved")
    return ca_private_key

def _get_and_save_ca_cert_from_input(outdir, filepath):
    # Get CA Certificate Data from file
    ca_cert = get_ca_cert_from_file(filepath)
    if not ca_cert:
        return
    log.debug("CA Cert data recieved")
    # Save CA cert if given as input
    ret_status = save_cert(ca_cert,
                           os.path.join(outdir, CACERT_FILENAME))
    if not ret_status:
        return
    log.debug("CA Cert saved")
    return ca_cert

def _get_mqtt_endpoint(is_local, is_input_file):
    log.debug("Getting mqtt endpoint")

    if not is_input_file:
        if is_local:
            node_mfg = Node_Mfg(None)
        else:
            session = Session()
            token = session.get_access_token()
            if not token:
                return None
            node_mfg = Node_Mfg(token)
    else:
        node_mfg = Node_Mfg(None)
        is_local = True

    endpoint = node_mfg.get_mqtthostname(is_local)
    # The get_mqtthostname API returns a tuple: (mqtt_host, mqtt_cred_host)
    # For endpoint purposes we only need the mqtt_host string.
    if isinstance(endpoint, tuple):
        mqtt_host = endpoint[0]
    else:
        mqtt_host = endpoint
    # Normalize falsy values to empty string to avoid type issues with len()
    if not mqtt_host:
        return ""
    return mqtt_host

def _set_data(node_count, common_outdir, is_local, is_input_file, mqtt_host):

    log.debug("Set data")
    log.debug('Generating node ids for '
                'number of nodes: {}'.format(node_count))
    node_ids_file = ""

    if not is_input_file:
        if is_local:
            # Generate <node_count> node ids
            log.debug("Locally generate node Ids")
            node_id_file_data = gen_node_id_local(node_count)
            if not node_id_file_data:
                log.error("Error generating node Ids locally")
                return None, None
            node_mfg = Node_Mfg(None)
            node_id_file_data = gen_node_id_local(node_count)
            if not node_id_file_data:
                log.error("Error generating node Ids locally")
                return None, None
        else:
            # Get current login session token
            # Re-login if session expired
            session = Session()
            token = session.get_access_token()
            if not token:
                return None, None
            node_mfg = Node_Mfg(token)
            # Generate <node_count> node ids
            node_id_file_url = node_mfg.gen_node_id(node_count)
            if not node_id_file_url:
                log.error("Generate node ids failed")
                return None, None
            # Download node ids file from url
            log.info("Downloading node ids file")
            node_id_file_data = download_from_url(node_id_file_url)

            if not node_id_file_data:
                log.error("Download file from url failed")
                return None, None

        # Save node ids data received into a file
        node_ids_file = save_to_file(node_id_file_data, common_outdir,
                                 filename_prefix="node_ids")
        if not node_ids_file:
            return None, None
        log.info("Node ids file saved at location: {}".format(node_ids_file))

    # Save mqtt endpoint into a file if available
    if mqtt_host:
        endpoint_file = save_to_file(mqtt_host, common_outdir,
                                    dest_filename=MQTT_ENDPOINT_FILENAME)
        if not endpoint_file:
            return None, None
        log.info("MQTT endpoint saved at location: {}".format(endpoint_file))
        # Get mqtt_cred_host directly from the API
        if not is_input_file:
            if is_local:
                node_mfg = Node_Mfg(None)
            else:
                node_mfg = Node_Mfg(token) if 'token' in locals() else Node_Mfg(None)

            mqtt_host_data = node_mfg.get_mqtthostname(is_local)
            if mqtt_host_data and isinstance(mqtt_host_data, tuple) and len(mqtt_host_data) >= 2:
                mqtt_cred_host = mqtt_host_data[1]
                if mqtt_cred_host:
                    mqtt_cred_endpoint_file = save_to_file(mqtt_cred_host, common_outdir,
                                                        dest_filename=MQTT_CRED_HOST_FILENAME)
                    if mqtt_cred_endpoint_file:
                        log.info("MQTT credential endpoint saved at location: {}".format(mqtt_cred_endpoint_file))

    return node_ids_file, mqtt_host

def gen_node_id_local(node_count):
    '''
    Generate list of node ids

    :param node_cnt: Number of node ids to get
    :type node_cnt: int
    '''
    try:
        log.debug('Generating node ids locally: {}'.format(node_count))

        node_list = []

        # Using shortuuid to generate node_ids in consistent with rainmaker node_ids
        for i in range(node_count):
            node_list.append(shortuuid.uuid())
        log.info('Request for generating node ids: {} is successful'.format(node_count))

        return ",".join(node_list)
    except KeyboardInterrupt:
        log.error("\nGenerate node Ids failed")
    except Exception as err:
        log.error("Generate node Ids failed")
        if len(str(err)) > 0:
            log.error("Error: {}".format(err))


def _extra_config_files_checks(outdir, extra_config, extra_values, file_id):
    log.debug("Extra config file checks")
    set_to_false = None
    if extra_config and not extra_values:
        log.info('ADDITIONAL_VALUES file must also be provided in config along with ADDITIONAL_CONFIG file.')
        set_to_false = False
    if file_id and file_id in ['node_id']:
        log.info('`node_id` is the default fileid. '
                    'Any new fileid provided as input must be a key in the '
                    'ADDITIONAL_VALUES file provided in config.')
        set_to_false = False
    if file_id and file_id not in ['node_id'] and not extra_values:
        log.info('Fileid provided must have corresponding values in ADDITIONAL_VALUES file in config. '
                    'Please provide ADDITIONAL_VALUES file in config.')
        set_to_false = False
    '''
    if extra_values and file_id and file_id not in ['node_id'] and not extra_config:
        log.info('Fileid provided must be a config key. Please provide ADDITIONAL_CONFIG file '
                    'alongwith ADDITIONAL_VALUES file in config.')
        set_to_false = False
    '''
    if extra_values:
        log.debug("Verifying mfg files input")
        # Verify mfg files
        verify_mfg_files(outdir, extra_config, extra_values, file_id)
    if set_to_false is False:
        return False
    return True


def generate_device_cert(vars=None):
    '''
    Generate Device Certificate

    :param vars: `count` as key - Number of Node Ids
                                  for generating certificates
    :type vars: str

    :param vars: `fileid` as key - File Identifier
    :type vars: str

    :param vars: `cacertfile` as key - Name of file containing CA Certificate
    :type vars: str

    :param vars: `cakeyfile` as key - Name of file containing CA Private Key
    :type vars: str

    :param vars: `outdir` as key - Output directory to save
                                   generated Device Certificate,
                                   defaults to current directory
    :type vars: str

    :raises Exception: If there is any exception while generating
                       Device Certificate(s)
            KeyboardInterrupt: If there is a keyboard interrupt by user

    :param vars: `cloud` as key - This is to determine whether to use cloud-based node id generation (default: False, uses local)
    :type vars: bool
    
    :param vars: `local` as key - Redundant flag for local generation (already default), kept for compatibility
    :type vars: bool

    :param vars: `inputfile` as key - This is the node_ids.csv file containing pre-generated node ids
    :type vars: str

    :return: None on Failure
    :rtype: None
    '''
    try:
        log.debug("Generate device certificates")

        node_count = int(vars['count'])

        extra_config = get_param_from_config('ADDITIONAL_CONFIG')
        extra_values = get_param_from_config('ADDITIONAL_VALUES')

        # Warn if --count is being overridden by --inputfile or ADDITIONAL_VALUES
        input_node_ids_file = vars.get('inputfile')
        if input_node_ids_file:
            if vars['count'] and int(vars['count']) > 0:
                log.warn("\nWARNING: --count argument is ignored because --inputfile is provided. The number of node IDs will be determined by the input file.\n")
        elif extra_values:
            if vars['count'] and int(vars['count']) > 0:
                log.warn("\nWARNING: --count argument is ignored because ADDITIONAL_VALUES is specified in the config. The number of node IDs will be determined by the values CSV file.\n")

        if not node_count and not extra_values and not input_node_ids_file:
            log.error('\nAtleast one of the following must be provided: --count (argument to specify number of node ids), ADDITIONAL_VALUES (in config to specify count of node ids using rows in a CSV file), --inputfile (argument to specify node ids in a CSV file)')
            return
        elif not node_count and extra_values and input_node_ids_file:
            log.info('\nNOTE: Both --inputfile and ADDITIONAL_VALUES are provided. The number of node IDs will be determined by the input file.\n')
        elif node_count <= 0 and not extra_values and not input_node_ids_file:
            ret_status = _cli_arg_check(None, '--count <count>',
                                    err_msg='<count> must be > 0')
            if not ret_status:
                return
        # Init
        file_id = vars['fileid']
        if len(file_id) == 0:
            file_id = None

        prov_type = BLUETOOTH
        if vars['prov']:
            prov_type = vars['prov']

        prov_prefix = "PROV"
        if vars['prov_prefix']:
            prov_prefix = vars['prov_prefix']

        # Set output dirname
        outdir = _set_output_dir(vars['outdir'])

        # Extra config files checks
        ret_status = _extra_config_files_checks(outdir, extra_config, extra_values, file_id)
        if not ret_status:
            return

        if extra_values:
            node_count = count_extra_values_file_rows(extra_values)

        # Initialize start and length for prefixing filenames
        prefix_num = vars.get('prefix_num')
        if prefix_num:
            if len(prefix_num) != 2:
                raise Exception("Both start and length must be provided together for --prefix_num")
            start, length = prefix_num
        else:
            start, length = 1, 6  # default values

         # find the no. of didgits in the start
        start_digits = len(str(start))
        # raise error if length is not greater than or equal to start_digits
        # and if the length is not greater than or equal to number of digits in (start + count)-1
        if int(length) < start_digits or int(length) < len(str(int(start) + int(vars['count'])-1)):
            raise Exception("Length must be greater than or equal to number of digits in start and the last node id using the count, i.e. {}".format(int(start) + int(vars['count'])-1))

        # Set default file id
        if not file_id:
            file_id = 'node_id'

        # Create output directory for all common files generated
        common_outdir = _gen_common_files_dir(outdir)

        # If cloud = false (default) we will generate node Ids locally
        is_local = not vars["cloud"]

        is_node_id_file = False
        node_id_list_unique = []
        if input_node_ids_file:
            # Validate node_ids.csv file by trying to get node Ids from the file
            node_id_list = get_nodeid_from_file(input_node_ids_file)
            if not node_id_list:
                log.error("Node Ids not found in the input file : {}".format(input_node_ids_file))
                raise Exception("Invalid Input file.")
            node_id_list_unique = [*set(node_id_list)]
            is_node_id_file = True

        # Get mqttendpoint
        endpoint = _get_mqtt_endpoint(is_local, is_node_id_file)
        if endpoint is None:
            return

        # Generate CA Cert and CA Key
        ca_cert_filepath = vars['cacertfile']
        ca_key_filepath = vars['cakeyfile']
        log.debug("CA Cert filename input: {}".format(ca_cert_filepath))
        log.debug("CA Key filename input: {}".format(ca_key_filepath))

        if not ca_cert_filepath and not ca_key_filepath:
            ca_cert, ca_private_key = generate_ca_cert(vars=vars, outdir=outdir, common_outdir=common_outdir, cli_call=False, mqtt_endpoint=endpoint)
        if ca_cert_filepath and not ca_key_filepath:
            raise Exception("CA key file is not provided")
        if ca_key_filepath and not ca_cert_filepath:
            raise Exception("CA cert file is not provided")

        _print_keyboard_interrupt_message()
        log.info('Files generated will be stored '
                'in directory: {}'.format(outdir))

        # Extract the endpoint prefix using regex
        ca_prefix = re.match(MQTT_PREFIX_SUBFOLDER_REGEX, endpoint)
        if ca_prefix:
            endpointprefix = ca_prefix.group(1)

        # Get paths for ca_certificates folder
        ca_certificates_cwd = _set_output_dir_cacert(None, endpointprefix)
        ca_cert_filepath_original = os.path.join(ca_certificates_cwd, CACERT_FILENAME)
        ca_key_filepath_original = os.path.join(ca_certificates_cwd, CA_KEY_FILENAME)

        # Get and save CA Certificate from file
        if len(ca_cert_filepath) != 0:
            ca_cert = _get_and_save_ca_cert_from_input(common_outdir, ca_cert_filepath)
            if not os.path.exists(ca_cert_filepath_original):
                ca_cert = get_ca_cert_from_file(ca_cert_filepath)
                if not ca_cert:
                    return
                log.debug("CA Cert data recieved from input path")
                # Save CA cert if given as input
                ret_status = save_cert(ca_cert,ca_cert_filepath_original)
                if not ret_status:
                    return
                log.debug("CA Cert saved in ca_certificates and common batch folder")

        # Get and save CA Private Key from file
        if len(ca_key_filepath) != 0:
            ca_private_key = _get_and_save_ca_key_from_input(common_outdir, ca_key_filepath)
            if not os.path.exists(ca_key_filepath_original):
                ca_private_key = get_ca_key_from_file(ca_key_filepath)
                if not ca_private_key:
                    return
                log.debug("CA Key data recieved from input path")
                # Save CA key if given as input
                ret_status = save_key(ca_private_key, ca_key_filepath_original)
                if not ret_status:
                    return
                log.debug("CA Key saved in ca_certificates and common batch folder")

        node_ids_file, endpoint = _set_data(node_count, common_outdir, is_local, is_node_id_file, endpoint)

        if is_node_id_file:
            node_ids_file = input_node_ids_file
        if not node_ids_file and len(endpoint)==0:
            raise Exception("")

        # Check for mqtt_cred_host if videostream option is enabled
        if vars['videostream']:
            log.info("Videostream option enabled, checking for mqtt_cred_host...")
            mqtt_cred_host_file = os.path.join(common_outdir, MQTT_CRED_HOST_FILENAME)
            if not os.path.exists(mqtt_cred_host_file):
                raise Exception("mqtt_cred_host not available. This is required when --videostream option is enabled. Check if the deployment is done with the videostream capability.")
            else:
                with open(mqtt_cred_host_file, 'r') as f:
                    mqtt_cred_host = f.read().strip()
                if not mqtt_cred_host:
                    raise Exception("mqtt_cred_host file exists but is empty. This is required when --videostream option is enabled. Check if the deployment is done with the videostream capability.")
                log.info("mqtt_cred_host is available: {}".format(mqtt_cred_host))

        # Get no_pop option
        no_pop = vars.get('no_pop', False)

        # Generate Device Cert and save into file
        certs_dest_filename = gen_and_save_certs(ca_cert,
                                                 ca_private_key,
                                                 node_ids_file,
                                                 file_id,
                                                 outdir,
                                                 endpoint,
                                                 prov_type, prov_prefix, node_id_list_unique, start, length, no_pop)
        if not certs_dest_filename:
            log.error("Generate device certificate failed")
            return
        log.info('\nNode Ids and device certificates saved at '
                 'location: {}'.format(certs_dest_filename))
        # Generate binaries
        log.info("\nGenerating binaries for the device certficates generated")
        gen_cert_bin(outdir, file_id, start, length)
        log.info('\nYou can now run: \npython rainmaker_admin_cli.py certs '
                 'devicecert register --inputfile {} '
                 '(Register Generated Device Certificate(s))'.format(certs_dest_filename))

    except KeyboardInterrupt:
        log.error("\nGenerate device certificate failed")
    except Exception as err:
        log.error("Generate device certificate failed")
        if len(str(err)) > 0:
            log.error("Error: {}".format(err))

def _get_md5_checksum(filename):
    chunk_size = 4096
    hash_md5 = hashlib.md5()
    with open(filename, "rb") as inputfile:
        for chunk in iter(lambda: inputfile.read(chunk_size), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def _remove_empty_lines(input_file):
    ##Remove empty lines if present from csv file
    with open(input_file) as in_file:
        with open("output_file.csv", 'w', newline='') as out_file:
            writer = csv.writer(out_file)
            for row in csv.reader(in_file):
                if row:
                    writer.writerow(row)
    ##delete existing input_file before renaming
    if os.path.exists(input_file):
        os.remove(input_file)
    os.rename('output_file.csv',input_file)
    return None

def _check_file_type(input_file):
    header_str = "certs"
    cert_str = "BEGIN CERTIFICATE"

    try:
        _remove_empty_lines(input_file)
    except Exception as e:
        log.error("\nError Validating Input file.Please check the input file.")
        return False


    with open(input_file, 'r', newline=None) as inputfile:
        header_data = inputfile.readline()
        if header_str in header_data:
            cert_data = inputfile.readline()
            if cert_str in cert_data:
                return True
        log.error("\nInput file is invalid. Please provide file containing the certificates")
        return False

def register_device_cert(vars=None):
    '''
    Register Uploaded Device Certificate

    :param vars: `inputfile` as key - Name of file containing
                                      node ids and device certificates
                 `type` as key - Node Type
                 `model` as key - Node Model
                 `groupname` as key - Name of the group to which
                                      nodes are to be added
                 `parent_groupname` as key - Name of the parent group to which this newly created group will be a child group
                 `subtype` as key - Node SubType
                 `tags` as key - Comma separated strings of tags to be attached to the nodes.(eg: location:Pune,office:espressif)
    :type vars: str

    :raises Exception: If there is any exception while
                       registering Device Certificate(s)
            KeyboardInterrupt: If there is a keyboard interrupt by user

    :return: None on Failure
    :rtype: None
    '''
    try:
        log.debug("Register device certificate")
        ret_status = _cli_arg_check(vars['inputfile'], '--inputfile <csvfilename>')
        if not ret_status:
            return

        is_valid_type = _check_file_type(vars['inputfile'])
        if not is_valid_type:
            return

        _print_keyboard_interrupt_message()

        # Get current login session token
        # Re-login if session expired
        session = Session()
        curr_email_id = session.get_curr_user_creds()
        token = session.get_access_token()
        if not token:
            log.error("Register device certificate failed")
            return
        refresh_token = session.get_refresh_token()
        if not refresh_token:
            log.error("Register device certificate failed")
            return
        # Get filename from input path
        basefilename = os.path.basename(vars['inputfile'])
        node_mfg = Node_Mfg(token)


        # Check if super admin's SES is verified
        ses_configured = check_ses_status(token)
        if not ses_configured:
            log.error("\nWARNING!!! Either of the following pre-requisites needs to be met before registering device certificates:")
            log.error("1. Rainmaker deployment's SES is still in sandbox(Not in production).")
            log.error("2. SuperAdmin's SES Email is not verified.")
            log.error("Without either of these pre-requisites, you will not receive emails of job status like success or failure.")
            log.error("\nIf this a concern, please abort this job, go to AWS SES Console and get the SuperAdmin's email verified, or apply for an SES production deployment.")
            while True:
                confirmation = input("Do you want to ignore the warning and continue anyway? (y/n): ").strip().lower()
                if confirmation in ['y', 'yes']:
                    break
                elif confirmation in ['n', 'no']:
                    log.error("Device certificate registration aborted")
                    sys.exit(1)
                log.error("Invalid input. Please enter 'y' or 'n'")

        # validate parent groupname i.e to check if it exists and also check if it's level 0 group
        parent_group_name = vars['parent_groupname']
        group_name=vars['groupname']

        parent_group_id = ""
        if parent_group_name:
            if group_name == parent_group_name:
                log.error("Groupname and parent_groupname should not be same")
                return
            is_present, parent_group_id = node_mfg.validate_groupnames(parent_group_name, parent_group_id)
            if is_present and not parent_group_id:
                log.error("Invalid parent_groupname as parent_groupname should not be the subgroup/children group.")
                return

        #Validate The groupname if the group is level 0 group if it exists
        if group_name:
            is_present, group_id = node_mfg.validate_groupnames(group_name, parent_group_id)
            if is_present and not group_id:
                log.error("Either provide the groupname with no parent or subgroup along with it's parent groupname")
                return

        # Validate force and update_nodes
        force = vars['force']
        update_nodes = vars['update_nodes']
        node_policies = vars['node_policies']
        if update_nodes and node_policies:
            log.error("--node_policies option cannot be used together with --update_nodes.")
            return
        valid_node_policies = ["mqtt", "videostream", ""]
        if node_policies:
            # Handle comma-separated values
            policies_list = [policy.strip() for policy in node_policies.split(',')]
            for policy in policies_list:
                if policy not in valid_node_policies:
                    log.error(f"Invalid value for --node_policies: '{policy}'. Valid values are 'mqtt', 'videostream', or leave empty.")
                    return
        if force or update_nodes:
            log.warn("\nWARNING: Ensure your backend version is 2.7.1 or higher if using the force or update_nodes flag.")
        #validate tags if present
        tags=vars['tags']
        if tags:
            # Validations for the CSV file and tags
            csvValidator = CsvValidator(vars['inputfile'])
            tags = csvValidator.are_valid(tags)
            if not tags:
                log.error("Error ocurred while validating the tags and the csv file.")
                return
        # Get URL to upload Device Certificate to
        cert_upload_url,request_id = node_mfg.get_cert_upload_url(basefilename)
        if not cert_upload_url:
            log.error("Upload Device Certificate Failed.")
            return

        if not request_id:
            log.warn("\nWARNING: Your cloud version appears to be below 2.8.0. Please upgrade to access the latest changes. Continuing with the older version.")

        # Upload Device Certificate file to S3 Bucket
        cert_upload = upload_cert(cert_upload_url, vars['inputfile'])
        if not cert_upload:
            log.error("Failed to upload Device Certificates")
            return
        else:
            log.info("Device certificate uploaded")

        # Get MD5 Checksum for input file
        md5_checksum = _get_md5_checksum(vars['inputfile'])
        node_type=vars['type']
        node_model=vars['model']
        subtype = vars['subtype']

        if not node_type and not node_model and not group_name and not subtype and not parent_group_name and not tags and not force and not update_nodes:
            conti=True
            log.warn("\nWARNING: type, model, group name, subtype, tags, force, update_nodes and parent groupname are absent.")
            while conti:
                goahead=input("Do you wish to continue? (y/n):")
                if goahead=="y" or goahead=="Y":
                    conti=False
                elif goahead=="n" or goahead=="N":
                    log.info("You can provide type, model, group name , subtype, force, parent groupname, update_nodes and tags using flags --type,--model,--groupname,--subtype, --force,--parent_groupname,--update_nodes ,--tags. ")
                    return
                else:
                    log.error("Please enter a valid input.")

        # Register Device Certificate
        job_request_id = node_mfg.register_cert_req(basefilename, md5_checksum, refresh_token, node_type, node_model, group_name, parent_group_id, parent_group_name, subtype, tags, force, update_nodes, request_id, node_policies)
        if not job_request_id:
            log.error("Request to register device certificate failed")
            return
        else:
            log.info('Request to register device certificate is successful\n')
            log.info('Certificate registration will take some time\n'
                     'You will receive the status on '
                     'your email-id: {}'.format(curr_email_id))

        log.info('\nYou can also run following command to check status: \n'
                 'python rainmaker_admin_cli.py certs devicecert getcertstatus '
                 '--requestid {} '
                 '(Get Device Certificate Registration '
                 'Status)'.format(job_request_id))

    except KeyboardInterrupt:
        log.error("\nRegister device certificate failed")
    except Exception as e:
        log.error("Error: {}".format(e))

def get_register_device_cert_status(vars=None):
    '''
    Get Status of Device Certificate Registration Request

    :param vars: `requestid` as key - Request Id of device
                                      certificate registration request
    :type vars: str

    :raises Exception: If there is any exception while getting
                       device certificate registration status
            KeyboardInterrupt: If there is a keyboard interrupt by user

    :return: None on Failure
    :rtype: None
    '''
    try:
        log.debug("Get register device cert status")
        ret_status = _cli_arg_check(vars['requestid'], '--requestid <requestid>')
        if not ret_status:
            return

        _print_keyboard_interrupt_message()

        # Get current login session token
        # Re-login if session expired
        session = Session()
        curr_email_id = session.get_curr_user_creds()
        token = session.get_access_token()
        if not token:
            log.error("Get device certificate registration request failed")
            return

        node_mfg = Node_Mfg(token)

        # Register Device Certificate
        cert_register_status = node_mfg.get_register_cert_status(
            vars['requestid'])
        log.info("Device certificate registration status: {}".format(
            cert_register_status))
        log.info('You will receive the status on '
                'your email-id: {}'.format(curr_email_id))
        return

    except KeyboardInterrupt:
        log.error("\nRegister device certificate failed")
    except Exception as e:
        log.error("Error: {}".format(e))

def _verify_serverconfig_exists():
    if not os.path.exists(SERVER_CONFIG_FILE):
        log.error('Server configuration is not set. Please configure using '
                  '<account serverconfig> CLI command')
        return False

    # If empty serverconfig file exists
    try:
        from rmaker_admin_lib.serverconfig import BASE_URL
    except ImportError:
        log.error('Server configuration is not set. '
                  'Please configure using <account serverconfig> CLI command')
        return False
    return True

def login(vars=None):
    '''
    User login

    :param vars: `email` as key - Email of user to login
    :type vars: str

    :raises Exception: If there is any exception while logging in
            KeyboardInterrupt: If there is a keyboard interrupt by user

    :return: None on Failure
    :rtype: None
    '''
    try:
        log.debug("Login command")
        ret_server_status = _verify_serverconfig_exists()
        if not ret_server_status:
            return

        ret_status = _cli_arg_check(vars['email'], '--email <emailid>')
        if not ret_status:
            return

        # Only show interrupt message when user interaction will be required
        password = vars.get('password') if vars.get('password') else None
        if password is None:
            _print_keyboard_interrupt_message()

        # Get current user email-id
        session = Session()
        curr_email_id = session.get_curr_user_creds()

        # Remove current login config if exists
        config = configmanager.Config()
        # Current email creds exist
        if curr_email_id:
            ret_status = config.remove_curr_login_config(email=curr_email_id)
            if not ret_status:
                return

        # User login
        user = User(vars['email'])
        # Login API call - use password if provided, otherwise prompt interactively
        user_login_data = user.login(password)
        if not user_login_data:
            log.error("Login failed.")
            return
        else:
            log.info("Login successful")

        # Save new user login config
        ret_status, cfg_file = config.save_config(user_login_data)
        if not ret_status:
            log.error('Failed to save login config '
                      'to file {}'.format(cfg_file))
            return
        else:
            log.info("Saved new login config in file: {}".format(cfg_file))

        log.info('\nYou can now run: \npython rainmaker_admin_cli.py certs '
                 'cacert generate -h (Generate CA Certificate)'
                 '\n\tor\npython rainmaker_admin_cli.py certs devicecert '
                 'generate -h (Generate Device Certificate(s))')
    except KeyboardInterrupt:
        log.error("\nLogin Failed")
    except Exception as e:
        log.error("Error: {}".format(e))

def configure_server(vars=None):
    '''
    Set Server Config

    :param vars: `endpoint` as key - Endpoint of server to use
    :type vars: str

    :raises Exception: If there is any exception while configuring server
            KeyboardInterrupt: If there is a keyboard interrupt by user

    :return: None on Failure
    :rtype: None
    '''
    try:
        log.debug("Configure server")
        ret_status = _cli_arg_check(vars['endpoint'], '--endpoint <endpoint>')
        if not ret_status:
            return

        config = configmanager.Config(config="server")
        ret_status = config.set_server_config(vars['endpoint'])
        if not ret_status:
            log.error("Failed to save server config")
            return
        else:
            log.info("Saved new server config")

        log.info('You can now run: \npython rainmaker_admin_cli.py account '
                 'login -h (Login)')
    except KeyboardInterrupt:
        log.error("\nServer config not set")
    except Exception as e:
        log.error("Error: {}".format(e))

def logout(vars=None):
    '''
    User logout

    :raises Exception: If there is any exception while logging out
            KeyboardInterrupt: If there is a keyboard interrupt by user

    :return: None on Failure
    :rtype: None
    '''
    try:
        log.debug("Logout command")
        ret_server_status = _verify_serverconfig_exists()
        if not ret_server_status:
            return

        # Get current session
        session = Session()
        curr_email_id = session.get_curr_user_creds()

        # Check if user is logged in
        if not curr_email_id:
            log.info("No active session found. User is not logged in.")
            return

        # Get tokens for logout API call
        access_token = session.get_access_token()
        refresh_token = session.get_refresh_token()
        config = configmanager.Config()

        # Always clean up local credentials, regardless of API call success
        def cleanup_local_credentials():
            try:
                import os
                if os.path.exists(config.config_file):
                    os.remove(config.config_file)
                    log.info("Local session data cleared for user: {}".format(curr_email_id))
                    return True
                else:
                    log.info("No local session data found to clear")
                    return True
            except Exception as cleanup_err:
                log.error("Failed to clear local session data: {}".format(cleanup_err))
                return False

        # Try to call logout API if we have valid tokens
        if access_token and refresh_token:
            try:
                user = User(curr_email_id)
                logout_success = user.logout(access_token, refresh_token)
                if logout_success:
                    log.info("Successfully logged out from server")
                else:
                    log.warn("Server logout failed, but proceeding with local cleanup")
            except Exception as api_err:
                log.warn("Error calling logout API: {}, but proceeding with local cleanup".format(api_err))
        else:
            log.info("No valid tokens found or session expired, proceeding with local cleanup")

        # Clean up local credentials (this should always happen)
        if not cleanup_local_credentials():
            return

        log.info("Logout completed successfully")

    except KeyboardInterrupt:
        log.error("\nLogout cancelled")
    except Exception as e:
        log.error("Error: {}".format(e))
