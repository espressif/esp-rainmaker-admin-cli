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
import sys
import hashlib
import datetime
import traceback
import distutils.dir_util
from rmaker_admin_lib.exceptions import FileError
from rmaker_admin_lib.node_mfg import Node_Mfg
from rmaker_admin_lib import configmanager
from rmaker_admin_lib.certs import *
from rmaker_admin_lib.certs import MQTT_ENDPOINT_FILENAME, gen_hex_str
from rmaker_admin_lib.http_ops import download_from_url, upload_cert
from rmaker_admin_lib.logger import log
from rmaker_admin_lib.user import User
from rmaker_admin_lib.session import Session
from rmaker_admin_lib.configmanager import SERVER_CONFIG_FILE
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
    if os.path.isfile(filepath):
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

def generate_ca_cert(vars=None, outdir=None, common_outdir=None, cli_call=True):
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
        log.debug("Generate CA certificate")
        if not outdir:
            # Set output dirname
            outdir = _set_output_dir(vars['outdir'])
        if not common_outdir:
            # Create output directory for all common files generated
            common_outdir = _gen_common_files_dir(outdir)
        
        # Set CA cert and CA key filepath
        cacert_filepath = os.path.join(common_outdir, CACERT_FILENAME)
        cakey_filepath = os.path.join(common_outdir, CA_KEY_FILENAME)

        if cli_call:
            _print_keyboard_interrupt_message()
            log.info('Files generated will be stored '
                    'in directory: {}'.format(outdir))
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
        # Save CA Private Key into a file
        ret_status = save_key(ca_private_key, cakey_filepath)
        if not ret_status:
            return
        # Generate CA Certificate
        cacert = generate_cacert(ca_cert_cfg_values, ca_private_key)
        if not cacert:
            print("Failed to generate CA certificate")
            return
        log.info('CA Certificate generated successfully '
                 'in directory: {}\n'.format(common_outdir))
        # Save CA Certificate into a file
        cacert_filepath = os.path.join(common_outdir, CACERT_FILENAME)
        ret_status = save_cert(cacert, cacert_filepath)
        if not ret_status:
            return

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

def _set_data(node_count, common_outdir):
    # Get current login session token
    # Re-login if session expired
    log.debug("Set data")
    session = Session()
    token = session.get_access_token()
    if not token:
        return None, None

    node_mfg = Node_Mfg(token)
    log.debug('Generating node ids for '
                'number of nodes: {}'.format(node_count))
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

    # Save mqtt endpoint into a file
    endpoint = node_mfg.get_mqtthostname()
    endpoint_file = save_to_file(endpoint, common_outdir,
                                 dest_filename=MQTT_ENDPOINT_FILENAME)
    if not endpoint_file:
        return None, None
    log.info("Endpoint saved at location: {}".format(endpoint_file))    
    return node_ids_file, endpoint_file

def _extra_config_files_checks(outdir, extra_config, extra_values, file_id):
    log.debug("Extra config file checks")
    set_to_false = None
    if extra_config and not extra_values:
        log.info('ADDITIONAL_VALUES file must also be provided in config '
                    'alongwith ADDITIONAL_CONFIG file.')
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
    if extra_config or extra_values:
        log.debug("Verifying mfg files input")
        # Verify mfg files
        verify_mfg_files(outdir, extra_config, extra_values, file_id)
    if set_to_false is False:
        return False
    return True

def _fileid_check(file_id, node_count, extra_values):
    log.debug("Fileid check")
    if file_id:
        # Verify fileid count
        ret_status = verify_fileid_count(extra_values, file_id, node_count)
        if not ret_status:
            log.error("Count: {} provided is greater than the values for fileid: {} in file: {}".format(
                node_count,
                file_id,
                extra_values))
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

    :return: None on Failure
    :rtype: None
    '''
    try:
        log.debug("Generate device certificates")
        node_count = int(vars['count'])
        ret_status = _cli_arg_check(node_count, '--count <count>',
                                    err_msg='<count> must be > 0')
        if not ret_status:
            return
        
        # Init
        file_id = vars['fileid']
        if len(file_id) == 0:
            file_id = None
        prov_type = None
        if vars['prov']:
            prov_type = vars['prov']        
        
        # Set output dirname
        outdir = _set_output_dir(vars['outdir'])
        
        # Extra config files checks
        extra_config = get_param_from_config('ADDITIONAL_CONFIG')
        extra_values = get_param_from_config('ADDITIONAL_VALUES')
        ret_status = _extra_config_files_checks(outdir, extra_config, extra_values, file_id)
        if not ret_status:
            return
        
        # Fileid checks
        ret_status = _fileid_check(file_id, node_count, extra_values)
        if not ret_status:
            return

        # Set default file id
        if not file_id:
            file_id = 'node_id'
        
        # Create output directory for all common files generated
        common_outdir = _gen_common_files_dir(outdir)
        
        # Generate CA Cert and CA Key
        ca_cert_filepath = vars['cacertfile']
        ca_key_filepath = vars['cakeyfile']
        log.debug("CA Cert filename input: {}".format(ca_cert_filepath))
        log.debug("CA Key filename input: {}".format(ca_key_filepath))
        if not ca_cert_filepath and not ca_key_filepath:
            ca_cert, ca_private_key = generate_ca_cert(vars=vars, outdir=outdir, common_outdir=common_outdir, cli_call=False)
        if ca_cert_filepath and not ca_key_filepath:
            raise Exception("CA key file is not provided")
        if ca_key_filepath and not ca_cert_filepath:
            raise Exception("CA cert file is not provided")
        
        _print_keyboard_interrupt_message()
        log.info('Files generated will be stored '
                'in directory: {}'.format(outdir))
        # Get and save CA Certificate from file
        if len(ca_cert_filepath) != 0:
            ca_cert = _get_and_save_ca_cert_from_input(common_outdir, ca_cert_filepath)
        
        # Get and save CA Private Key from file
        if len(ca_key_filepath) != 0:
            ca_private_key = _get_and_save_ca_key_from_input(common_outdir, ca_key_filepath)
        # Set data
        node_ids_file, endpoint_file = _set_data(node_count, common_outdir)
        if not node_ids_file and not endpoint_file:
            raise Exception("")
        # Generate Device Cert and save into file
        certs_dest_filename = gen_and_save_certs(ca_cert,
                                                 ca_private_key,
                                                 node_ids_file,
                                                 file_id,
                                                 outdir,
                                                 endpoint_file,
                                                 prov_type)
        if not certs_dest_filename:
            log.error("Generate device certificate failed")
            return
        log.info('\nNode Ids and device certificates saved at '
                 'location: {}'.format(certs_dest_filename))
        # Generate binaries
        log.info("\nGenerating binaries for the device certficates generated")
        gen_cert_bin(outdir, file_id)
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

def _check_file_type(input_file):
    header_str = "certs"
    cert_str = "BEGIN CERTIFICATE"
    with open(input_file, 'r', newline='\n') as inputfile:
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

        # Get filename from input path
        basefilename = os.path.basename(vars['inputfile'])
        node_mfg = Node_Mfg(token)
        # Get URL to upload Device Certificate to
        cert_upload_url = node_mfg.get_cert_upload_url(basefilename)
        if not cert_upload_url:
            log.error("Upload Device Certificate Failed.")
            return

        # Upload Device Certificate file to S3 Bucket
        cert_upload = upload_cert(cert_upload_url, vars['inputfile'])
        if not cert_upload:
            log.error("Failed to upload Device Certificates")
            return
        else:
            log.info("Device certificate uploaded")

        # Get MD5 Checksum for input file
        md5_checksum = _get_md5_checksum(vars['inputfile'])

        # Register Device Certificate
        request_id = node_mfg.register_cert_req(basefilename, md5_checksum)
        if not request_id:
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
                 'Status)'.format(request_id))
    
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
        # Login API call
        user_login_data = user.login()
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
