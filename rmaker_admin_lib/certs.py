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

import csv
from io import open
import os
import sys
import time
import json
import binascii
import datetime
import pyqrcode
import distutils.dir_util
from rmaker_admin_lib.constants import CSV_EXTENSION, NAMESPACE_KEY, REPEAT_TAG
from tools import mfg_gen
from rmaker_admin_lib.logger import log
from dateutil.relativedelta import relativedelta

try:
    from future.moves.itertools import zip_longest
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives.asymmetric import rsa, ec
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
MQTT_CRED_HOST_FILENAME = "mqtt_cred_host.txt"
CERT_VALIDATION_YEARS = 100

# Set input arguments required by manufacturing tool
# for creating NVS Partition Binary


class Mfg_Args():
    def __init__(self, dest_config_filename, dest_values_filename,
                 data, outdir, keygen, file_id, prefix, prefix_num):
        self.conf = dest_config_filename
        self.values = dest_values_filename
        if data:
            self.size = data['BINARY_SIZE']
        else:
            self.size = data
        self.outdir = outdir
        self.fileid = file_id
        self.prefix = prefix
        self.prefix_num = prefix_num
        # Set version=2, multipage blob support enabled
        self.version = 2
        self.keygen = keygen
        self.inputkey = None
        # These must be None, there must be no input from user for these params
        self.keyfile = None
        self.input = None
        self.output = None
        self.key_protect_hmac = False

        log.debug('Arguments set to send to manufacturing tool for '
                  'creating NVS partiton binaries')
        log.debug('conf: {}, values: {}, size: {}, '
                  'outdir: {}, version: {} '
                  'keygen: {}, inputkey: {}, keyfile: {}, '
                  'input: {}, output: {}, fileid: {}, prefix: {}, prefix_num: {}'.format(
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
                      self.fileid,
                      self.prefix,
                      self.prefix_num))


def save_to_file(file_data, output_dir,
                 filename_prefix=None, dest_filename=None,
                 ext=CSV_EXTENSION):
    '''
    Save data to a file, with a special case for node IDs.

    :param file_data: Data to save to file
    :type file_data: str or bytes

    :param output_dir: Output directory to store data
    :type output_dir: str

    :param filename_prefix: Prefix for Filename
    :type filename_prefix: str

    :param dest_filename: Name of destination file
    :type dest_filename: str

    :param ext: File extension (default is '.csv')
    :type ext: str

    :return: Path of the saved file
    :rtype: str
    '''
    file_mode = 'wb+'
    try:
        log.debug("file_data is : {}".format(file_data))
        dest_filepath = None

        # Ensure the output directory exists
        if not os.path.isdir(output_dir):
            os.makedirs(output_dir)
            log.debug("Directory created: {}".format(output_dir))

        # If no destination filename is provided, use the _set_filename function
        if not dest_filename:
            dest_filepath = _set_filename(filename_prefix=filename_prefix, outdir=output_dir, ext=ext)
            if not dest_filepath:
                return None
        else:
            dest_filepath = os.path.join(output_dir, dest_filename)

        log.debug("Destination filename set: {}".format(dest_filepath))
        log.debug("Saving in output directory: {}".format(output_dir))

        # Special case for saving node IDs in a CSV format
        if filename_prefix == "node_ids" and ext == '.csv':
            # Decode file_data if it is bytes
            if isinstance(file_data, bytes):
                file_data = file_data.decode('utf8')

            # Split node IDs by comma and remove empty entries
            node_ids = [node_id.strip() for node_id in file_data.split(',') if node_id.strip()]
            log.debug("Node IDs to save: {}".format(node_ids))

            # Write node IDs to CSV file with a header
            with open(dest_filepath, mode='w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(['node_id'])  # Write header
                for node_id in node_ids:
                    writer.writerow([node_id])  # Write each node ID in a new row
            log.debug("Node IDs successfully written to file")
            return dest_filepath
        # General case for other data (write file only if it's not node_ids)
        else:
            if ext == '.png':
                with open(dest_filepath, 'wb+') as f:
                    file_data.png(f, scale=4)
            else:
                try:
                    if not isinstance(file_data, bytes):
                        log.debug("Converting data to bytes")
                        file_data = file_data.encode('utf8')
                except AttributeError:
                    log.debug("Converting data to JSON")
                    file_data = json.dumps(file_data)
                    file_mode = 'w+'

                log.debug("Writing data to file")
                with open(dest_filepath, file_mode) as f:
                    try:
                        f.write(file_data)
                    except TypeError:
                        f.write(file_data.decode('utf8'))

            log.debug("Data successfully written to file: {}".format(dest_filepath))
            return dest_filepath

    except Exception as err:
        log.error(f"Error occurred while saving data to file {dest_filepath}: {err}")
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
    :type key: RSA or ECDSA Private Key

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

def _save_nodeid_cert_and_qrcode_to_file(node_id, dev_cert, qrcode_payload, dest_csv_file):
    '''
    Save Node ID, Certificate, and QR code to file.

    :param node_id: Node ID
    :type node_id: str

    :param dev_cert: Device Certificate
    :type dev_cert: x509 Certificate

    :param qrcode_payload: QR code payload, can contain commas
    :type qrcode_payload: dict (or str if already serialized)

    :param dest_csv_file: Destination CSV file
    :type dest_csv_file: str or file object (must support write operations)
    '''
    try:
        delimiter = ","
        newline = "\n"
        double_quote = "\""

        # Convert certificate to PEM format (string) and wrap it in quotes
        dev_cert_bytes = dev_cert.public_bytes(encoding=serialization.Encoding.PEM)
        dev_cert_str = double_quote + dev_cert_bytes.decode('utf-8').replace('"', '""') + double_quote

        # Serialize qrcode_payload and ensure it is properly escaped
        if isinstance(qrcode_payload, dict):
            qrcode_str = double_quote + json.dumps(qrcode_payload).replace('"', '""') + double_quote
        else:
            qrcode_str = double_quote + str(qrcode_payload).replace('"', '""') + double_quote

        # Prepare new CSV data
        log.debug("Saving node id, cert, and qrcode to file: {}".format(dest_csv_file))
        new_data = [node_id, dev_cert_str, qrcode_str]

        data_to_write = delimiter.join(new_data) + newline
       # Writing to file
        if isinstance(dest_csv_file, str): # If `dest_csv_file` is a string (if file path provided)
            with open(dest_csv_file, 'a') as f:
                f.write(data_to_write)
        else:
            dest_csv_file.write(data_to_write)  # If not a string, assume `dest_csv_file` is a file object and write directly

        log.debug("Node Id, Cert, and QR code saved to file successfully")
        return True

    except FileError as file_err:
        log.error(FileError('Error occurred while saving node id, cert, and QR code to '
                            'file {} error: {} \n'.format(dest_csv_file, file_err)))
    except Exception as err:
        log.error(FileError('Error occurred while saving node id, cert, and QR code to '
                            'file {} error: {} \n'.format(dest_csv_file, err)))
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

def count_extra_values_file_rows(extra_values_file):
    '''
    Count the number of entries in the values file for node count
    '''
    log.debug("Verify fileid count")
    with open(extra_values_file, 'r') as values_file:
        rows = values_file.readlines()
    # first row will be of all keys (column names)
    return len(rows)-1

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
    Get Node Id from the specified "node_id" column in a CSV file.

    :param filename: Filename containing Node Ids in a column named "node_id"
    :type filename: str
    :return: List of Node IDs from the "node_id" column
    :rtype: list
    '''
    try:
        log.debug("Getting node ids from file: {}".format(filename))

        nodeid_list = []

        # Open the file and read it using the csv module
        with open(filename, mode='r') as csvfile:
            reader = csv.DictReader(csvfile)  # Reads the file as a dictionary with headers
            log.debug("CSV headers: {}".format(reader.fieldnames))

            # Check if the required "node_id" column is present
            if 'node_id' not in reader.fieldnames:
                raise ValueError(f"'node_id' column not found in file: {filename}")

            # Extract all values from the "node_id" column
            for row in reader:
                node_id = row['node_id'].strip()  # Strip whitespace from the value
                if node_id:  # Add non-empty node IDs to the list
                    nodeid_list.append(node_id)

        log.debug("Node IDs extracted: {}".format(nodeid_list))
        return nodeid_list

    except Exception as err:
        log.error(f"Error occurred while getting node ids from file {filename}: {err}")
        raise

def _write_header_to_dest_csv(dest_csv_file):
    '''
    Write header to file

    :param dest_csv_file: Destination csv file to save header
    :type dest_csv_file: str
    '''
    delimiter = ","
    newline = "\n"
    header = ["node_id", "certs", "qrcode"]
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

def extract_cn_from_certificate(cert_pem_data):
    """
    Extract Common Name (CN) from a PEM certificate

    :param cert_pem_data: Certificate data in PEM format as string
    :return: Common Name (CN) from certificate, or None if not found
    :rtype: str or None
    """
    try:
        # Convert string to bytes if needed
        if isinstance(cert_pem_data, str):
            cert_pem_data = cert_pem_data.encode('utf-8')

        # Load the certificate
        cert = load_pem_x509_certificate(cert_pem_data, default_backend())

        # Extract the subject and find CN
        subject = cert.subject
        for attribute in subject:
            if attribute.oid == NameOID.COMMON_NAME:
                return attribute.value

        return None
    except Exception as e:
        log.error(f"Error extracting CN from certificate: {e}")
        return None

def validate_cert_cn_matches_node_id(node_id, cert_pem_data):
    """
    Validate that the Common Name (CN) in the certificate matches the node_id

    :param node_id: The node ID to validate against
    :param cert_pem_data: Certificate data in PEM format as string
    :return: True if CN matches node_id, False otherwise
    :rtype: bool
    """
    cn = extract_cn_from_certificate(cert_pem_data)
    if cn is None:
        log.error(f"Could not extract CN from certificate for node {node_id}")
        return False

    if cn != node_id:
        log.error(f"Certificate CN '{cn}' does not match node_id '{node_id}'")
        return False

    log.debug(f"Certificate CN '{cn}' matches node_id '{node_id}'")
    return True

def _generate_cert(subject_name=None, issuer_name=None,
                   public_key=None, ca_key=None, ca=False):
    '''
    Generate x509 Certificate

    :param subject_name: Subject Name
    :type subject_name: str

    :param issuer_name: Issuer Name
    :type issuer_name: str

    :param public_key: Public Key
    :type public_key: RSA or ECDSA Public Key

    :param ca_key: CA Key
    :type ca_key: RSA or ECDSA Private Key

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

def generate_private_key(key_type='rsa'):
    '''
    Generate Private Key

    :param key_type: Type of key to generate ('rsa' or 'ecdsa')
    :type key_type: str
    '''
    try:
        log.debug("Generating {} private key".format(key_type))

        if key_type.lower() == 'ecdsa':
            # Generate ECDSA P-256 key (much faster than RSA)
            private_key = ec.generate_private_key(
                ec.SECP256R1(),  # P-256 curve
                backend=default_backend()
            )
            log.debug("Generated ECDSA P-256 private key")
        else:
            # Generate RSA key (legacy support)
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            log.debug("Generated RSA 2048-bit private key")

        log.debug("Private key generated successfully: {}".format(type(private_key)))
        return private_key
    except Exception as err:
        log.debug("Error: {}. Could not generate {} private key".format(err, key_type))
        return False

def generate_cacert(cacert_info, ca_private_key):
    '''
    Generate CA Certificate

    :param cacert_info: CA certificate info
    :type cacert_info: dict

    :param ca_private_key: CA Private Key
    :type ca_private_key: RSA or ECDSA Private Key
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
    :type private_key: RSA or ECDSA Private Key

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
                        common_name=None, key_type='rsa'):
    '''
    Generate Device Certificate

    :param outdir: Output Directory
    :type outdir: str

    :param ca_cert: CA Certificate
    :type ca_cert: x509 Certificate

    :param ca_private_key: CA Private Key
    :type ca_private_key: RSA or ECDSA Private Key

    :param common_name: Common Name
    :type common_name: str
    '''
    try:
        log.debug("Generating device cert")

        log.debug("Generating {} private key for device certificate".format(key_type))
        private_key = generate_private_key(key_type=key_type)
        if not private_key:
            return False, False
        log.debug("{} private key generated for device certificate".format(key_type.upper()))

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
                        endpoint, mqtt_cred_host, cert, cert_key, random_str, qrcode_payload, curr_extra_values):
    log.debug("Writing to values file for manufacturing tool")
    log.debug('Writing data to values file: values_file:{} id:{} '
              'node_id:{} endpoint:{} mqtt_cred_host:{} cert:{} cert_key:{} random_str:{} qrcode_payload:{}'.format(
                  dest_values_file, id, node_id, endpoint, mqtt_cred_host, cert, cert_key, random_str, qrcode_payload))

    # Ensure the directory exists
    os.makedirs(os.path.dirname(dest_values_file), exist_ok=True)

    # Open the file in append mode
    with open(dest_values_file, mode='a', newline='') as csvfile:
        writer = csv.writer(csvfile, quotechar='"', quoting=csv.QUOTE_MINIMAL)

        # Format the qrcode_payload correctly
        formatted_qrcode = json.dumps(qrcode_payload)  # JSON-encoded string

        # Create the row
        row = [
            id,
            node_id,
            endpoint,
            mqtt_cred_host or "",  # Use empty string if mqtt_cred_host is None
            cert,
            cert_key,
            random_str,
            formatted_qrcode  # Enclosed properly
        ]

        # Append curr_extra_values if they exist
        if curr_extra_values:
            row.extend(curr_extra_values)

        # Write the row to the CSV file
        writer.writerow(row)

    log.debug("Done creating values file")

# Function from mfg_gen, added here to verify extra config and values files
def create_temp_files(args):
    new_filenames = []
    for filename in [args.conf, args.values]:
        if filename:  # Check if the file is present (handling case when extra_config.csv is None)
            name, ext = os.path.splitext(filename)
            new_filename = name + '_tmp' + ext
            strip_blank_lines(filename, new_filename)
            new_filenames.append(new_filename)
    return new_filenames

# Function from mfg_gen, added here to verify extra config and values files
def strip_blank_lines(input_filename, output_filename):
    with open(input_filename, 'r') as read_from, open(output_filename,'w', newline='') as write_to:
        for line in read_from:
            if not line.isspace():
                write_to.write(line)

# Function from mfg_gen, added here to verify extra config and values files
def verify_file_format(args):
    keys_in_config_file = []
    keys_in_values_file = []
    keys_repeat = []

    # Verify and process the config file if present
    if args.conf:
        log.info("Verifying given extra config file")
        # Verify config file has .csv extension
        conf_name, conf_extension = os.path.splitext(args.conf)
        if conf_extension != CSV_EXTENSION:
            raise SystemExit('Error: config file: %s does not have the .csv extension.' % args.conf)

        # Verify config file is not empty
        if os.stat(args.conf).st_size == 0:
            raise SystemExit('Error: config file: %s is empty.' % args.conf)

        # Extract keys from config file
        with open(args.conf, 'r') as config_file:
            config_file_reader = csv.reader(config_file, delimiter=',')
            for config_data in config_file_reader:
                if NAMESPACE_KEY not in config_data:
                    keys_in_config_file.append(config_data[0])
                if REPEAT_TAG in config_data:
                    keys_repeat.append(config_data[0])

    # Verify and process the values file if present
    if args.values:
        log.info("Verifying given extra values file")
        # Verify values file has .csv extension
        values_name, values_extension = os.path.splitext(args.values)
        if values_extension != CSV_EXTENSION:
            raise SystemExit('Error: values file: %s does not have the .csv extension.' % args.values)

        # Verify values file is not empty
        if os.stat(args.values).st_size == 0:
            raise SystemExit('Error: values file: %s is empty.' % args.values)

        # Extract keys from values file
        with open(args.values, 'r') as values_file:
            values_file_reader = csv.reader(values_file, delimiter=',')
            keys_in_values_file = next(values_file_reader)

    # Verify file identifier exists in values file
    if args.fileid and args.values:
        if args.fileid not in keys_in_values_file:
            raise SystemExit(
                'Error: target_file_identifier: %s does not exist in values file.\n' % args.fileid
            )
    else:
        args.fileid = 1

    return keys_in_config_file, keys_in_values_file, keys_repeat

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
        file_id,
        'node',
        None)
    log.debug("Verifying mfg files")

    # Verifying extra_config and extra_values files
    temp_files = create_temp_files(mfg_args)

    # Assign values only if they exist
    if len(temp_files) == 2:  # Both files were processed
        mfg_args.conf, mfg_args.values = temp_files
    elif len(temp_files) == 1:  # Only one file was processed
        if mfg_args.conf:  # Check which file was processed
            mfg_args.conf = temp_files[0]
            mfg_args.values = None
        else:
            mfg_args.conf = None
            mfg_args.values = temp_files[0]
    else:  # No files were processed
        mfg_args.conf = None
        mfg_args.values = None
        log.debug("No files were processed")
    # Verify input config and values file format
    keys_in_config_file, keys_in_values_file, keys_repeat = verify_file_format(mfg_args)

    log.debug("Extra config and values files verified")

def gen_cert_bin(outdir, file_id, prefix_num_start, prefix_num_digits):
    '''
    Generate binaries for certificate(s)

    :param outdir: Output Directory
    :type outdir: str

    :param prefix_num_start: Starting number for prefix (default is 1)
    :type prefix_num_start: str

    :param prefix_num_digits: Number of digits for prefix (default is 6)
    :type prefix_num_digits: str
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
        file_id,
        'node',
        (int(prefix_num_start),int(prefix_num_digits)))
    log.debug("Generating binaries")
    mfg_gen.generate(mfg_args)
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
        'mqtt_host,data,binary',
        'mqtt_cred_host,data,binary',
        'client_cert,file,binary',
        'client_key,file,binary',
        'random,data,hex2bin'
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

def generate_qrcode(random_hex, prov_type, prov_prefix, no_pop=False):
    '''
    Generate payload for QR code

    :param random_hex: Random info generated (128 bytes)
    :type random_hex: str

    :param prov_type: Provisioning type
    :type prov_type: str

    :param prov_prefix: Provisioning prefix
    :type prov_prefix: str

    :param no_pop: Generate QR code without pop field
    :type no_pop: bool
    '''
    payload = {}
    # Set version as v1 (default)
    version = 'v1'
    # Set provisioning name (last 3 bytes - 6 hex chars of random info)
    prov_name = prov_prefix+'_' + random_hex[-6:]
    # Set transport
    transport = prov_type
    # Generate payload
    payload['ver'] = version
    payload['name'] = prov_name
    if not no_pop:
        # Set pop as first 4 bytes (8 hex chars) of random info
        pop = random_hex[0:8]
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

def _gen_prov_data(node_id_dir, node_id_dir_str, qrcode_outdir, random_hex_str, prov_type, prov_prefix, no_pop=False):
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
    qrcode_payload, qrcode = generate_qrcode(random_hex_str, prov_type, prov_prefix, no_pop)
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
    return True, qrcode_payload

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
    values_keys = 'id,node_id,mqtt_host,mqtt_cred_host,client_cert,client_key,random,qrcode'
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
                       file_id, outdir, endpoint, prov_type, prov_prefix, node_id_list_unique, prefix_num_start, prefix_num_digits, no_pop=False, key_type='rsa'):
    '''
    Generate and save device certificate

    :param ca_cert: CA Certificate
    :type ca_cert: x509 Certificate

    :param ca_private_key: CA Private Key
    :type ca_private_key: RSA or ECDSA Private Key

    :param input_filename: Name of file containing Node Id's
    :type input_filename: str

    :param file_id: File Identifier
    :type file_id: str

    :param outdir: Output Directory
    :type outdir: str

    :param endpoint: MQTT Endpoint
    :type endpoint: str

    :param prefix_num_start: Starting number for prefix (default is 1)
    :type prefix_num_start: str

    :param prefix_num_digits: Number of digits for prefix (default is 6)
    :type prefix_num_digits: str
    '''
    file_id_suffix = None
    cnt = int(prefix_num_start)
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
            prefix_number = f'{int(cnt):0{prefix_num_digits}}'
            node_id_dir_str = 'node-' + str(prefix_number) + "-" + str(file_id_suffix)
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

            # Generate provisioning data
            # QR code image and str
            prov_status, qrcode_payload = _gen_prov_data(node_id_dir, node_id_dir_str, qrcode_outdir, random_hex_str, prov_type, prov_prefix, no_pop)
            if not prov_status:
                return
            # Print QR code status
            _print_status(cnt, step_cnt, msg='QRcode payload and image generated')

            # Create values file for input to
            # Manufacturing Tool to generate binaries

            # Try to read mqtt_cred_host from file
            mqtt_cred_host = None
            mqtt_cred_host_file = os.path.join(common_outdir, MQTT_CRED_HOST_FILENAME)
            if os.path.exists(mqtt_cred_host_file):
                try:
                    with open(mqtt_cred_host_file, 'r') as f:
                        mqtt_cred_host = f.read().strip()
                    log.debug("Read mqtt_cred_host from file: {}".format(mqtt_cred_host))
                except Exception as e:
                    log.debug("Error reading mqtt_cred_host file: {}".format(e))

            _create_values_file(
                dest_values_filename,
                cnt,
                node_id,
                endpoint,
                mqtt_cred_host,
                cert_dest_filename,
                key_dest_filename,
                random_hex_str,
                qrcode_payload,
                curr_extra_values)

            # Generate device certificate
            dev_cert, priv_key = generate_devicecert(
                outdir,
                ca_cert,
                ca_private_key,
                common_name=node_id,
                key_type=key_type)
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
            ret_status = _save_nodeid_cert_and_qrcode_to_file(
                node_id,
                dev_cert,
                qrcode_payload,
                dest_csv_file)
            if not ret_status:
                return False
            log.debug("Number of certificates generated and saved")
            _print_status(cnt, step_cnt, msg='Certificates generated')

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
