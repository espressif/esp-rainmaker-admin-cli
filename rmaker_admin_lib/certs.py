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


from __future__ import absolute_import, print_function, unicode_literals

from io import open
import os
import sys
import time
import json
import binascii
import datetime
import pyqrcode
import distutils.dir_util
from tools import mfg_gen
from rmaker_admin_lib.logger import log
from dateutil.relativedelta import relativedelta

try:
    from future.moves.itertools import zip_longest
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509 import load_pem_x509_certificate
    from cryptography.hazmat.backends import default_backend
    from configparser import ConfigParser
    from builtins import str
except ImportError as err:
    log.error("{}\nPlease run `pip install -r requirements.txt`\n".format(
        err))
    sys.exit(1)

from rmaker_admin_lib.exceptions import FileError

path_sep = os.sep
sys.path.insert(0, '..{}config{}'.format(path_sep, path_sep))

MFG_CONFIG_FILENAME = "config.csv"
MFG_VALUES_FILENAME = "values.csv"
MFG_BINARY_CONFIG_FILENAME = "config{}binary_config.ini".format(path_sep)
MQTT_ENDPOINT_FILENAME = "endpoint.txt"
CERT_VALIDATION_YEARS = 100

# Set input arguments required by manufacturing tool
# for creating NVS Partition Binary


class Mfg_Args():
    def __init__(self, dest_config_filename, dest_values_filename,
                 data, outdir, keygen, file_id):
        self.conf = dest_config_filename
        self.values = dest_values_filename
        if data:
            self.size = data['BINARY_SIZE']
        else:
            self.size = data
        self.outdir = outdir
        # Set version=2, multipage blob support enabled
        self.version = 2
        self.keygen = keygen
        self.inputkey = None
        # These must be None, there must be no input from user for these params
        self.keyfile = None
        self.input = None
        self.output = None
        self.fileid = file_id
        log.debug('Arguments set to send to manufacturing tool for '
                  'creating NVS partiton binaries')
        log.debug('conf: {}, values: {}, size: {}, '
                  'outdir: {}, version: {} '
                  'keygen: {}, inputkey: {}, keyfile: {}, '
                  'input: {}, output: {}, fileid: {}'.format(
                      self.conf,
                      self.values,
                      self.size,
                      self.outdir,
                      self.version,
                      self.keygen,
                      self.inputkey,
                      self.keyfile,
                      self.input,
                      self.output,
                      self.fileid))


def save_to_file(file_data, output_dir,
                 filename_prefix=None, dest_filename=None,
                 ext='.csv'):
    '''
    Save text data to file

    :param file_data: Data to save to file
    :type file_data: str

    :param output_dir: Output directory to store data
    :type output_dir: str

    :param filename_prefix: Prefix for Filename
    :type filename_prefix: str

    :param dest_filename: Name of destination file
    :type dest_filename: str
    '''
    file_mode = 'wb+'
    try:
        dest_filepath = None

        if not os.path.isdir(output_dir):
            os.makedirs(output_dir)
            log.debug("Directory created: {}".format(output_dir))

        if not dest_filename:
            dest_filepath = _set_filename(filename_prefix=filename_prefix,
                                          outdir=output_dir, ext=ext)
            if not dest_filepath:
                return None
        else:
            dest_filepath = os.path.join(output_dir, dest_filename)

        log.debug("Destination filename set: {}".format(dest_filepath))
        log.debug("Saving in output directory: {}".format(output_dir))

        # Write image to file (used for qrcode)
        if ext == '.png':
            with open(dest_filepath, 'wb+') as f:
                file_data.png(f, scale=4)
        else:
            try:
                # Write file data to file
                if not isinstance(file_data, bytes):
                    log.debug("Converting data to bytes")
                    file_data = file_data.encode('utf8')
            except AttributeError:
                log.debug("Converting data to json")
                file_data = json.dumps(file_data)
                file_mode = 'w+'

            log.debug("Writing data to file")
            with open(dest_filepath, file_mode) as f:
                try:
                    f.write(file_data)
                except TypeError:
                    f.write(file_data.decode('utf8'))

        return dest_filepath
    except Exception as err:
        log.error(FileError('Error occurred while saving node ids to '
                            'file {} error: {} \n'.format(
                                dest_filepath,
                                err)))
        raise

def save_cert(cert, filepath):
    '''
    Save certificate to file

    :param cert: Certificate
    :type cert: x509 Certificate

    :param filepath: Destination filepath with filename
    :type filepath: str
    '''
    try:
        log.debug("Saving Certificate to file: {}".format(filepath))
        cert_bytes = cert.public_bytes(encoding=serialization.Encoding.PEM,)

        with open(filepath, "wb+") as f:
            f.write(cert_bytes)
        log.debug("Certificate saved to file {}".format(filepath))
        return True

    except FileError as file_err:
        log.debug(FileError('Error occurred while saving cert to '
                            'file {} error: {} \n'.format(
                                filepath,
                                file_err)))
        log.error('Error: Failed to save cert in file {}'.format(filepath))
    except Exception as err:
        log.debug("Error {}. Cannot save certificate".format(err))
        log.error('Error: Failed to save cert in file {}'.format(filepath))

def save_key(key, filepath):
    '''
    Save key to file

    :param key: Private Key
    :type key: RSA Private Key

    :param filepath: Destination filepath with filename
    :type filepath: str
    '''
    try:
        log.debug("Saving Private key to file: {}".format(filepath))
        key_bytes = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption())

        with open(filepath, "wb+") as f:
            f.write(key_bytes)
        log.debug("Key saved to file at location: {}".format(filepath))
        return True

    except FileError as file_err:
        log.debug(FileError('Error occurred while saving key to file {} '
                            'error: {} \n'.format(filepath, file_err)))
        log.error('Error: Failed to save key in file {}'.format(filepath))
    except Exception as err:
        log.debug(FileError('Error occurred while saving key to file {} '
                            'error: {} \n'.format(filepath, err)))
        log.error('Error: Failed to save key in file {}'.format(filepath))

def _save_nodeid_and_cert_to_file(node_id, dev_cert, dest_csv_file):
    '''
    Save Node Id and Certificate to file

    :param node_id: Node Id
    :type node_id: str

    :param dev_cert: Device Certificate
    :type dev_cert: x509 Certificate

    :param dest_csv_file: Destination CSV file
    :type dest_csv_file: str
    '''
    try:
        delimiter = ","
        newline = "\n"
        double_quote = "\""
        dev_cert_bytes = dev_cert.public_bytes(
            encoding=serialization.Encoding.PEM,)
        dev_cert_str = double_quote + dev_cert_bytes.decode('utf-8') + \
            double_quote
        log.debug("Saving node id and cert to file: {}".format(
            dest_csv_file))
        new_data = [node_id, dev_cert_str]
        data_to_write = delimiter.join(new_data) + newline
        dest_csv_file.write(data_to_write)
        log.debug("Node Id and Cert saved to file: {}".format(
            dest_csv_file))
        log.debug("Node id and certificate saved to file successfully")
        return True
    except FileError as file_err:
        log.error(FileError('Error occurred while saving node id and cert to '
                            'file {} error: {} \n'.format(
                                dest_csv_file,
                                file_err)))
    except Exception as err:
        log.error(FileError('Error occurred while saving node id and cert to '
                            'file {} error: {} \n'.format(
                                dest_csv_file,
                                err)))
        raise

def _set_filename(filename_prefix=None, outdir=None, ext=None):
    '''
    Set filename

    :param filename_prefix: Filename Prefix
    :type filename_prefix: str

    :param outdir: Output directory
    :type outdir: str

    :param ext: Extension of file
    :type ext: str
    '''
    try:
        backslash = os.sep
        filename = ""

        # Create directory if does not exist
        if not os.path.isdir(outdir):
            log.debug("Creating dir: {}".format(outdir))
            distutils.dir_util.mkpath(outdir)
            log.debug("Directory created: {}".format(outdir))

        filename = "".join([filename_prefix, ext])
        log.debug("Setting base filename: {}".format(filename))

        filename = "".join([outdir, backslash, filename])
        log.debug("Setting {} ext filename: {}".format(ext, filename))

        return filename
    except Exception as err:
        raise Exception(err)

def verify_fileid_count(extra_values_file, fileid, count):
    '''
    Verify count is less than or equal to
    number of values for fileid 
    '''
    log.debug("Verify fileid count")
    with open(extra_values_file, 'r') as values_file:
        rows = values_file.readlines()
    if count > (len(rows) - 1):
        return False
    return True

def _check_file_format(rows_in_file):
    '''
    Check file format

    :param rows_in_file: Rows in file
    :type rows_in_file: list
    '''
    # Remove empty lines if present
    log.debug("Input rows: {}".format(rows_in_file))
    log.debug("Check file format")
    for row in rows_in_file:
        log.debug("Checking for row: {}".format(row))
        if isinstance(row, str):
            log.debug("Removing newline from list element: {}".format(row))
            row_str = row.strip()
            if len(row_str) == 0:  # empty string
                log.debug("List element length is zero, removing from list: {}".format(row))
                rows_in_file.remove(row)
    return rows_in_file  # return the row containting node ids

def get_ca_key_from_file(filename):
    '''
    Get CA Key from file

    :param filename: Filename for saving CA Private Key
    :type filename: str
    '''
    try:
        path_sep = os.sep
        filename = os.path.expanduser(filename.rstrip(path_sep))
        log.debug("Get CA Key from file: {}".format(filename))
        ca_key = None
        with open(filename, "rb") as key_file:
            ca_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend())
        log.debug("CA Key received.")
        return ca_key
    except FileError as file_err:
        log.error(FileError('Error occurred while getting key to '
                            'file {} error: {} \n'.format(
                                filename,
                                file_err)))
        return
    except Exception as err:
        raise Exception(err)

def get_ca_cert_from_file(filename):
    '''
    Get CA Certificate from file

    :param filename: Filename for saving CA Certificate
    :type filename: str
    '''
    try:
        path_sep = os.sep
        filename = os.path.expanduser(filename.rstrip(path_sep))
        log.debug("Saving CA Certificate to file: {}".format(filename))
        ca_cert = None
        with open(filename, "rb") as crt_file:
            ca_cert = x509.load_pem_x509_certificate(
                crt_file.read(),
                default_backend())
        log.debug("CA certificate from file received")
        return ca_cert
    except FileError as file_err:
        log.error(FileError('Error occurred while getting cert to '
                            'file {} error: {} \n'.format(
                                filename,
                                file_err)))
        return
    except Exception as err:
        raise Exception(err)

def get_nodeid_from_file(filename):
    '''
    Get Node Id from file

    :param filename: Filename containing Node Ids
    :type filename: str
    '''
    try:
        log.debug("Getting node id from file: {}".format(filename))
        delimiter = ","
        with open(filename) as csvfile:
            rows_in_file = csvfile.readlines()
            file_data = _check_file_format(rows_in_file)
            log.debug("File data received: {}".format(file_data))
            nodeid_list = file_data[0].split(delimiter)
            log.debug("Node Ids list: {}".format(nodeid_list))
            nodeid_list = _check_file_format(nodeid_list)
            log.debug("Node Ids received from file: {}".format(nodeid_list))
            return nodeid_list
    except Exception as err:
        log.error(FileError('Error occurred while getting node ids from '
                            'file {}\n{}'.format(filename, err)))
        raise

def _write_header_to_dest_csv(dest_csv_file):
    '''
    Write header to file

    :param dest_csv_file: Destination csv file to save header
    :type dest_csv_file: str
    '''
    delimiter = ","
    newline = "\n"
    header = ["node_id", "certs"]
    log.debug("Writing header to csv file: {}".format(header))
    keys_to_write = delimiter.join(header)
    keys_to_write = keys_to_write + newline
    dest_csv_file.write(keys_to_write)
    return dest_csv_file

def load_existing_cert(cert_path):
    with open(cert_path, "rb") as cert_file:
        cert_data = cert_file.read()
    return load_pem_x509_certificate(cert_data, default_backend())

def load_existing_key(key_path):
    with open(key_path, "rb") as key_file:
        key_data = key_file.read()
    return serialization.load_pem_private_key(key_data, password=None, backend=default_backend())

def _generate_cert(subject_name=None, issuer_name=None,
                   public_key=None, ca_key=None, ca=False):
    '''
    Generate x509 Certificate

    :param subject_name: Subject Name
    :type subject_name: str

    :param issuer_name: Issuer Name
    :type issuer_name: str

    :param public_key: Public Key
    :type public_key: RSA Public Key

    :param ca_key: CA Key
    :type ca_key: RSA Private Key

    :param ca: Set if certificate is CA Certificate
    :type ca: bool
    '''
    try:
        # Setting start date to previous day to activate generated certificates immediately
        valid_from_date = datetime.datetime.today() - datetime.timedelta(days=1)

        log.debug('Generating certificate builder - subject_name:{} '
                  'issuer_name: {} ca: {}'.format(
                      subject_name,
                      issuer_name,
                      ca))
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(x509.Name(subject_name))
        builder = builder.issuer_name(x509.Name(issuer_name))
        cert_validation_period = relativedelta(years=CERT_VALIDATION_YEARS)
        builder = builder.not_valid_before(valid_from_date)
        builder = builder.not_valid_after(
            valid_from_date + cert_validation_period)
        builder = builder.serial_number(x509.random_serial_number())

        builder = builder.public_key(public_key)
        builder = builder.add_extension(
            x509.BasicConstraints(ca=ca, path_length=None), critical=True,
        )
        dev_certificate = builder.sign(
            private_key=ca_key, algorithm=hashes.SHA256(),
            backend=default_backend()
        )
        if not isinstance(dev_certificate, x509.Certificate):
            log.debug('Device Certificate Type is Wrong, '
                      'expected x509.Certificate')
            return False
        return dev_certificate
    except Exception as err:
        log.debug("Error: {}. Cannot generate device certificate".format(err))

def _create_subj_name_list(cacert_info):
    '''
    Create subject list for certificate

    :param cacert_info: CA certificate info
    :type cacert_info: dict
    '''
    try:
        log.debug("Create subject name list")
        subj_name = []
        if 'common_name' in cacert_info and cacert_info['common_name']:
            subj_name.append(x509.NameAttribute(
                NameOID.COMMON_NAME,
                cacert_info['common_name']))
        if 'org_name' in cacert_info and cacert_info['org_name']:
            subj_name.append(x509.NameAttribute(
                NameOID.ORGANIZATION_NAME,
                cacert_info['org_name']))
        if 'org_unit_name' in cacert_info and cacert_info['org_unit_name']:
            subj_name.append(x509.NameAttribute(
                NameOID.ORGANIZATIONAL_UNIT_NAME,
                cacert_info['org_unit_name']))
        if 'locality_name' in cacert_info and cacert_info['locality_name']:
            subj_name.append(x509.NameAttribute(
                NameOID.LOCALITY_NAME,
                cacert_info['locality_name']))
        if 'state_name' in cacert_info and cacert_info['state_name']:
            subj_name.append(x509.NameAttribute(
                NameOID.STATE_OR_PROVINCE_NAME,
                cacert_info['state_name']))
        if 'country_name' in cacert_info and cacert_info['country_name']:
            subj_name.append(x509.NameAttribute(
                NameOID.COUNTRY_NAME,
                cacert_info['country_name']))
        if 'email_addr' in cacert_info and cacert_info['email_addr']:
            subj_name.append(x509.NameAttribute(
                NameOID.EMAIL_ADDRESS,
                cacert_info['email_addr']))
        return subj_name
    except Exception as err:
        log.debug("Error: {}. Cannot create subject list".format(err))
        return False

def generate_private_key():
    '''
    Generate Private Key
    '''
    try:
        log.debug("Generating private key")
        # Generate Key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        log.debug("Generating private key: {}".format(private_key))
        return private_key
    except Exception as err:
        log.debug("Error: {}. Could not generate private key".format(err))
        return False

def generate_cacert(cacert_info, ca_private_key):
    '''
    Generate CA Certificate

    :param cacert_info: CA certificate info
    :type cacert_info: dict

    :param ca_private_key: CA Private Key
    :type ca_private_key: RSA Private Key
    '''
    try:
        log.info("\nGenerating CA Certificate")
        ca_public_key = ca_private_key.public_key()
        subj_name_list = _create_subj_name_list(cacert_info)
        if not subj_name_list:
            return False
        issuer_name = subj_name_list
        ca_cert = _generate_cert(
            subject_name=subj_name_list,
            issuer_name=issuer_name,
            public_key=ca_public_key,
            ca_key=ca_private_key,
            ca=True)
        if not ca_cert:
            return False
        return ca_cert
    except Exception as err:
        log.debug("Error: {} . Cannot create CA Certificate".format(err))

def generate_csr(private_key, common_name):
    '''
    Generate CSR

    :param private_key: Private Key
    :type private_key: RSA Private Key

    :param common_name: Common Name
    :type common_name: str
    '''
    try:
        log.debug("Generate CSR")
        # Generate CSR on host
        csr_builder = x509.CertificateSigningRequestBuilder()
        csr_builder = csr_builder.subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]))

        csr_builder = csr_builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        csr = csr_builder.sign(
            private_key, hashes.SHA256(), default_backend()
        )
        if not isinstance(csr, x509.CertificateSigningRequest):
            print('CSR Type Is Wrong, '
                  'expected x509.CertificateSigningRequest')
            return False
        return csr
    except Exception as err:
        raise Exception(err)

def generate_devicecert(outdir, ca_cert, ca_private_key,
                        common_name=None):
    '''
    Generate Device Certificate

    :param outdir: Output Directory
    :type outdir: str

    :param ca_cert: CA Certificate
    :type ca_cert: x509 Certificate

    :param ca_private_key: CA Private Key
    :type ca_private_key: RSA Private Key

    :param common_name: Common Name
    :type common_name: str
    '''
    try:
        log.debug("Generating device cert")

        log.debug("Generating private key")
        private_key = generate_private_key()
        if not private_key:
            return False, False
        log.debug("Private key generated")

        log.debug("Generating CSR")
        csr = generate_csr(private_key, str(common_name))
        if not csr:
            log.info("Failed to generate CSR")
            return False, False
        log.debug("CSR generated")

        dev_cert = _generate_cert(
            subject_name=csr.subject,
            issuer_name=ca_cert.subject,
            public_key=csr.public_key(),
            ca_key=ca_private_key)

        if not dev_cert:
            log.info("Certificate Not Generated")
            return False, False
        log.debug("Device certificate generated successfully")

        return dev_cert, private_key

    except Exception as err:
        raise Exception(err)

def _create_values_file(dest_values_file, id, node_id,
                        endpoint, cert, cert_key, random_str, curr_extra_values):
    log.debug("Writing to values file for manufacturing tool")
    log.debug('Writing data to values file: values_file:{} id:{} '
              'node_id:{} endpoint:{} cert:{} cert_key:{} random_str:{} '.format(
                  dest_values_file, id, node_id, endpoint, cert, cert_key, random_str))
    values_file = open(dest_values_file, 'a')
    values_file.write(str(id))
    values_file.write(',')
    values_file.write(str(node_id))
    values_file.write(',')
    values_file.write(endpoint)
    values_file.write(',')
    values_file.write(cert)
    values_file.write(',')
    values_file.write(cert_key)
    values_file.write(',')
    values_file.write(random_str)
    if curr_extra_values:
        for item in curr_extra_values:
            values_file.write(',')
            values_file.write(item)
    values_file.write("\n")
    values_file.seek(0)
    values_file.close()
    log.debug("Done creating values file")

def verify_mfg_files(outdir, config_filename, values_filename, file_id):
    '''
    Verify Mfg files format and data is valid
    '''
    common_outdir = os.path.join(outdir, 'common')
    mfg_args = Mfg_Args(
        config_filename,
        values_filename,
        None,
        None,
        None,
        file_id)
    log.debug("Verifying mfg files")
    # Only verify files, csv is not generated here
    mfg_gen.generate(mfg_args)
    log.debug("Mfg files verified")

def gen_cert_bin(outdir, file_id):
    '''
    Generate binaries for certificate(s)

    :param outdir: Output Directory
    :type outdir: str
    '''
    log.debug("Setting config arguments for generating binaries")
    common_outdir = os.path.join(outdir, 'common')
    dest_config_filename = os.path.join(common_outdir, MFG_CONFIG_FILENAME)
    dest_values_filename = os.path.join(common_outdir, MFG_VALUES_FILENAME)

    config = ConfigParser()
    config.read(MFG_BINARY_CONFIG_FILENAME)
    config.sections()

    keygen = config['DEFAULT'].getboolean('ENCR_ENABLED')
    log.debug("Mfg input args: config file: {}, values file: {} \
        config: {}, outdir: {}, keygen: {}".format(
            dest_config_filename,
            dest_values_filename,
            config['DEFAULT'],
            outdir,
            keygen
        ))
    mfg_args = Mfg_Args(
        dest_config_filename,
        dest_values_filename,
        config['DEFAULT'],
        outdir,
        keygen,
        file_id)
    log.debug("Generating binaries")
    mfg_gen.generate(mfg_args, create_csv=True)
    log.debug("Binaries generated")

def gen_hex_str(octets=64):
    """
    Generate random hex string, it is used as PoP

    :param octets: Number of octets in random hex string, length is (octets * 2)
                    defaults to 64,
    :type: octets: int

    :return: random hex string on Success, None on Failure
    :rtype: str|None
    """
    # Generate random hex string
    return binascii.b2a_hex(os.urandom(octets)).decode()

def _add_extra_config_file(config_csv_file):
    # Check if additonal config file is given
    # in the .ini file
    log.debug("Checking if extra config file exists")
    extra_config = get_param_from_config('ADDITIONAL_CONFIG')
    if not extra_config:
        return False

    comments_exist_in_file = False
    # Read file and add contents to main config file
    log.debug("Getting file contents...")
    with open(extra_config, 'r') as cfg_file:
        line = cfg_file.readline().strip()
        # Comments are skipped
        while line.startswith('#'):
            comments_exist_in_file = True
            line = cfg_file.readline().strip()
        config_csv_file.append(line)
        while True:
            key_line = cfg_file.readline().strip()
            if not len(key_line) > 0:
                break
            config_csv_file.append(key_line)
    return config_csv_file

def _create_mfg_config_file(outdir):
    # Set csv file data
    config_csv_file = [
        'rmaker_creds,namespace,',
        'node_id,data,binary',
        'mqtt_host,file,binary',
        'client_cert,file,binary',
        'client_key,file,binary',
        'random,file,hex2bin'
    ]

    # Check if additonal config file is given
    # in the .ini file
    ret_val = _add_extra_config_file(config_csv_file)
    # Update main config file if return is a success
    if ret_val:
        config_csv_file = ret_val

    log.debug("Final config csv file created: {}".format(config_csv_file))
    log.debug("Creating manufacturing config file")
    dest_config_filename = os.path.join(outdir, MFG_CONFIG_FILENAME)
    log.debug("Config file dest: {}".format(dest_config_filename))
    with open(dest_config_filename, 'w+') as info_file:
        for input_line in config_csv_file:
            info_file.write(input_line)
            info_file.write("\n")
    log.debug("Manufacturing config file created")
    return dest_config_filename

def generate_qrcode(random_hex, prov_type):
    '''
    Generate payload for QR code
    
    :param random_hex: Random info generated (128 bytes)
    :type random_hex: str

    :param prov_type: Provisioning type
    :type prov_type: str
    '''
    payload = {}
    # Set version as v1 (default)
    version = 'v1'
    # Set pop as first 4 bytes (8 hex chars) of random info
    pop = random_hex[0:8]
    # Set provisioning name (last 3 bytes - 6 hex chars of random info)
    prov_name = 'PROV_' + random_hex[-6:]
    # Set transport
    transport = prov_type
    # Generate payload
    payload['ver'] = version
    payload['name'] = prov_name
    payload['pop'] = pop
    payload['transport'] = transport
    log.debug("QR code payload generated: {}".format(payload))
    
    # Create qr code
    # All parameter values like version, mode, error is set to auto
    payload_json_str = json.dumps(payload)
    log.debug("Creating image for payload: {}".format(payload_json_str))
    qrcode_gen = pyqrcode.create(payload_json_str)
    log.debug("QRcode generated")
    return payload, qrcode_gen

def _check_extra_values_file_exists():
    # Check if additonal config file is given
    # in the .ini file
    log.debug("Checking if extra values file exists...")
    extra_values_file = get_param_from_config('ADDITIONAL_VALUES')
    return extra_values_file
        
def get_param_from_config(param):
    log.debug("Getting param from config")
    param_val = True
    config = ConfigParser()
    config.read(MFG_BINARY_CONFIG_FILENAME)
    config.sections()
    try:
        param_val = config['DEFAULT'][param]
        log.debug("Param val received from config: {}".format(param_val))
        if param_val in ['None']:
            return False
        path_sep = os.sep
        param_val = os.path.expanduser(param_val.rstrip(path_sep))
        if os.path.isabs(param_val) is False:
            script_dir = os.getcwd()
            param_val = os.path.join(script_dir, param_val)
        log.debug("Param value is: {}".format(param_val))
    except (ValueError,KeyError):
        return False
    log.debug("Param value {} received from config".format(param_val))
    return param_val

def _read_extra_values_file_header(filename):
    log.debug("Read extra values file header")
    extra_values_file = open(filename, 'r')
    comments_exist_in_file = False
    line = extra_values_file.readline().strip()
    # Comments are skipped
    while line.startswith('#'):
        comments_exist_in_file = True
        line = extra_values_file.readline().strip()
    log.debug("Current line: {}".format(line))
    return extra_values_file, line

def _set_extra_values(line):
    log.debug("Additional values file exist in config")
    # Convert to list
    extra_keys_list = [ item.strip() for item in line.split(',') ]
    return extra_keys_list

def _gen_random_info(node_id_dir):
    log.debug("Generating random info")
    # Set destination filename to save random info str (PoP)
    random_info_str = 'random'
    # Save random str (used a PoP) into a file
    random_hex_str = gen_hex_str()
    random_str_file = save_to_file(random_hex_str, node_id_dir, filename_prefix=random_info_str, ext=".txt")
    if not random_str_file:
        return False, False
    log.debug("Random info generated")
    return random_hex_str, random_str_file

def _print_status(cnt, step_cnt, msg=None):
    if cnt % step_cnt == 0:
        curr_time = time.time()
        timestamp = datetime.datetime.fromtimestamp(
            curr_time).strftime('%H:%M:%S')
        log.info('\n[{:<6}][Current Status] {}: {}'.format(msg, timestamp, str(cnt)))

def _gen_prov_data(node_id_dir, node_id_dir_str, qrcode_outdir, random_hex_str, prov_type):
    '''
    Generate Provisioning data
    QR code image and string
    '''
    log.debug("Generating QR code")
    # Set destination filename to save QR code image (png format)
    qrcode_payload_str = 'qrcode'
    # QR code image filename str is same as the current node id dirname str
    qrcode_img_str = node_id_dir_str
    # Generate payload (qr code payload) and png (qr code image)
    qrcode_payload, qrcode = generate_qrcode(random_hex_str, prov_type)
    log.debug("QR code and payload generated")
    # Save qrcode payload
    payload_file = save_to_file(qrcode_payload, node_id_dir, filename_prefix=qrcode_payload_str, ext=".txt")
    if not payload_file:
        return
    log.debug("QR code payload saved to file")
    # Save qrcode image to file
    qrcode_img_file = save_to_file(qrcode, qrcode_outdir, filename_prefix=qrcode_img_str, ext=".png")
    if not qrcode_img_file:
        return
    log.debug("QR code image saved to file")
    return True

def _init_file(common_outdir):
    log.debug("In init file")
    # Setup destination filename if not provided
    dest_filename = _set_filename(
        filename_prefix="node_certs",
        outdir=common_outdir,
        ext=".csv")
    if not dest_filename:
        return False
    log.debug("Dest filename set to: {}".format(dest_filename))
    return dest_filename

def _init_dir(outdir):
    log.debug("In init dir")
    # Create output directory for all node details
    node_details_outdir = os.path.join(outdir, 'node_details')
    if not os.path.isdir(node_details_outdir):
        distutils.dir_util.mkpath(node_details_outdir)
        log.debug("Directory created: {}".format(node_details_outdir))
    log.debug("Node details outdir is set to: {}".format(node_details_outdir))
    # Create output directory for all common files generated
    common_outdir = os.path.join(outdir, 'common')
    if not os.path.isdir(common_outdir):
        distutils.dir_util.mkpath(common_outdir)
        log.debug("Directory created: {}".format(common_outdir))
    log.debug("Common outdir is set to: {}".format(common_outdir))
    # Create output directory for all qrcode image (png) files generated
    qrcode_outdir = os.path.join(outdir, 'qrcode')
    if not os.path.isdir(qrcode_outdir):
        distutils.dir_util.mkpath(qrcode_outdir)
        log.debug("Directory created: {}".format(qrcode_outdir))
    log.debug("QR code outdir is set to: {}".format(qrcode_outdir))
    return node_details_outdir, common_outdir, qrcode_outdir

def _get_curr_extra_value(extra_values_file):
    log.debug("Getting current extra value from extra values file")
    extra_values_line = extra_values_file.readline().strip()
    curr_extra_values = [ item.strip() for item in extra_values_line.split(',') ]
    return curr_extra_values

def _mfg_files_init(common_outdir, extra_keys_list):    
    log.debug("In mfg files init")
    # Set Manufacturing config file
    dest_config_filename = _create_mfg_config_file(common_outdir)
    # Open values file (needed for generating binary)
    log.debug("Creating values file for manufacturing tool")
    # Set final values  keys
    values_keys = 'id,node_id,mqtt_host,client_cert,client_key,random'
    if extra_keys_list:
        # Get each comma seperated value in line
        for item in extra_keys_list:
            values_keys = values_keys + "," + item
    log.debug("Final values keys: {}".format(values_keys))
    # Save to file
    dest_values_filename = os.path.join(common_outdir, MFG_VALUES_FILENAME)
    log.debug("Dest values filename: {}".format(dest_values_filename))
    values_file = open(dest_values_filename, 'w+')
    log.debug("Final values keys: {}".format(values_keys))
    values_file.write(values_keys)
    values_file.write("\n")
    values_file.seek(0)
    values_file.close()
    log.debug("Header keys written to csv values file successfully")
    return dest_config_filename, dest_values_filename

def _get_extra_values_filename():
    log.debug("Getting extra values filename")
    # Get extra values file data if exists
    extra_values_filename = _check_extra_values_file_exists()
    return extra_values_filename

def _get_extra_values_keys(header):
    log.debug("Getting extra values keys")
    extra_keys_list = []
    extra_keys_list = _set_extra_values(header)
    return extra_keys_list

def _certs_files_init(dest_filename):
    log.debug("In certs files init")
    # Open dest nodeid and certs csv file
    dest_csv_file = open(dest_filename, "w+")
    dest_csv_file = _write_header_to_dest_csv(dest_csv_file)
    log.debug('Node id and Cert header keys written '
                'to csv file successfully')
    return dest_csv_file

def gen_and_save_certs(ca_cert, ca_private_key, input_filename,
                       file_id, outdir, endpoint_file, prov_type, node_id_list_unique):
    '''
    Generate and save device certificate

    :param ca_cert: CA Certificate
    :type ca_cert: x509 Certificate

    :param ca_private_key: CA Private Key
    :type ca_private_key: RSA Private Key

    :param input_filename: Name of file containing Node Id's
    :type input_filename: str

    :param file_id: File Identifier
    :type file_id: str

    :param outdir: Output Directory
    :type outdir: str

    :param endpoint_file: Endpoint filename
    :type endpoint_file: str
    '''
    file_id_suffix = None
    max_filename_len = 6
    cnt = 1
    step_cnt = 100
    extra_keys = None
    extra_values_file_ptr = None
    
    log.debug("File Id recieved as user input: {}".format(file_id))
    try:
        # Init dir generate
        node_details_outdir, common_outdir, qrcode_outdir = _init_dir(outdir)
        # Init file generate
        dest_filename = _init_file(common_outdir)
        # Init Certs files 
        dest_csv_file = _certs_files_init(dest_filename)
        # Get extra values filename
        extra_values_filename = _get_extra_values_filename()
        if extra_values_filename:
            # Get extra values file and file headers
            extra_values_file_ptr, header = _read_extra_values_file_header(extra_values_filename)
            # Get extra values keys if exists
            extra_keys = _get_extra_values_keys(header)
        # Create the headers for the Manufacturing CSV config file
        dest_config_filename, dest_values_filename = _mfg_files_init(common_outdir, extra_keys)
        
        curr_extra_values = None

        # Print info
        log.info("\nRandom info will be saved at location: {}".format(node_details_outdir))
        log.info("QR code payload will be saved at location: {}".format(node_details_outdir))
        log.info("QR code image(png) will be saved at location: {}".format(qrcode_outdir))
        log.info("\nGenerating device certificates")
        
        # If node_id_list is already calculated in case of input file
        if node_id_list_unique:
            node_id_list = node_id_list_unique
        else:
            # Get Node Ids list from file
            node_id_list = get_nodeid_from_file(input_filename)
            if not node_id_list:
                print("Node ids not found in file: {}".format(input_filename))
                return False
        node_id_list = [i for i in node_id_list if i]

        # Generate and save cert for each node id
        for node_id in node_id_list:
           # Remove any spaces/newlines which may exist
            # at the start or end of the node id string
            node_id = node_id.strip()
            log.debug("Current node id: {}".format(node_id))
            # Set file id suffix
            if file_id == 'node_id':
                file_id_suffix = node_id
            # Get the values in ADDITIONAL_VALUES file
            if extra_values_filename:
                curr_extra_values = _get_curr_extra_value(extra_values_file_ptr)
                # Set file id suffix
                key_value_data = list(zip_longest(extra_keys, curr_extra_values))
                log.debug("Current key-value data: {}".format(key_value_data))
                for item in key_value_data:
                    if item[0] == file_id:
                        file_id_suffix = item[1]
                        log.debug("File Id suffix set to: {}".format(file_id_suffix))
                        if not file_id_suffix:
                            raise Exception('<count> provided is not equal to '
                                            'number of values for fileid: {} in file: {} '.format(
                                                file_id, extra_values_filename)) 

            # Create directory for node details for specific node id
            zeros_prefix_len = max_filename_len - len(str(cnt))
            zero_prefix_str = '0' * zeros_prefix_len
            node_id_dir_str='node-' + zero_prefix_str + str(cnt) + "-" + file_id_suffix
            node_id_dir = os.path.join(node_details_outdir, node_id_dir_str)
            if not os.path.isdir(node_id_dir):
                distutils.dir_util.mkpath(node_id_dir)
                log.debug("Directory created: {}".format(node_id_dir))

            # Set destination filename to save device certificates generated
            cert_dest_filename = _set_filename(
                filename_prefix='node',
                outdir=node_id_dir,
                ext=".crt")
            if not cert_dest_filename:
                return False

            # Set destination filename to save private keys
            # of certificates generated
            key_dest_filename = _set_filename(
                filename_prefix='node',
                outdir=node_id_dir,
                ext=".key")
            if not key_dest_filename:
                return False
            log.debug("Saving Key for Node Id: {} at location: {}".format(
                node_id,
                key_dest_filename))
            
            log.debug("Generating device certificate for node id: {}".format(
                node_id))

            # Get random info
            random_hex_str, random_str_file = _gen_random_info(node_id_dir)
            if not random_hex_str and not random_str_file:
                return
            
            # Print status
            _print_status(cnt, step_cnt, msg='Random str (used as PoP) generated')

            # Create values file for input to
            # Manufacturing Tool to generate binaries
            _create_values_file(
                dest_values_filename,
                cnt,
                node_id,
                endpoint_file,
                cert_dest_filename,
                key_dest_filename,
                random_str_file,
                curr_extra_values)

            # Generate device certificate
            dev_cert, priv_key = generate_devicecert(
                outdir,
                ca_cert,
                ca_private_key,
                common_name=node_id)
            if not dev_cert and not priv_key:
                return False
            log.debug('Saving Certificate for Node Id: {} '
                      'at location: {}'.format(
                          node_id,
                          cert_dest_filename))
            
            # Save certificate
            ret_status = save_cert(dev_cert, cert_dest_filename)
            if not ret_status:
                return False
            # Save private key
            ret_status = save_key(priv_key, key_dest_filename)
            if not ret_status:
                return False
            # Save node ids and certs together in a csv file
            # (used to upload and register the certificates)
            log.debug("Saving Node Id and Certificate to file: {}".format(
                dest_filename))
            ret_status = _save_nodeid_and_cert_to_file(
                node_id,
                dev_cert,
                dest_csv_file)
            if not ret_status:
                return False
            log.debug("Number of certificates generated and saved")
            _print_status(cnt, step_cnt, msg='Certificates generated')
            # Generate QR code
            if prov_type:
                # Generate provisioning data
                # QR code image and str
                prov_status = _gen_prov_data(node_id_dir, node_id_dir_str, qrcode_outdir, random_hex_str, prov_type)
                if not prov_status:
                    return
                # Print QR code status
                _print_status(cnt, step_cnt, msg='QRcode payload and image generated')
            cnt += 1
        log.info("\nTotal certificates generated: {}".format(str(cnt - 1)))
        # Cleanup
        dest_csv_file.seek(0)
        dest_csv_file.close()
        if extra_values_filename:
            extra_values_file_ptr.seek(0)
            extra_values_file_ptr.close()
        
        log.info("Device certificates generated successfully")
        return dest_filename

    except FileError as file_err:
        log.error(file_err)
    except Exception as err:
        raise Exception(err)
