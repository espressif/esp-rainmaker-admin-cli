- [ESP RainMaker Admin CLI](#esp-rainmaker-admin-cli)
  - [Introduction](#introduction)
  - [Getting the Admin CLI](#getting-the-admin-cli)
  - [Setup Build Environment](#setup-build-environment)
    - [Operating System requirements](#operating-system-requirements)
    - [Other requirements](#other-requirements)
    - [Installing dependencies](#installing-dependencies)
  - [Workflow](#workflow)
  - [Usage](#usage)
    - [Account Operations](#account-operations)
      - [Server Config](#server-config)
      - [Login](#login)
    - [Device Certificate Operations](#device-certificate-operations)
      - [Generate Device Certificates](#generate-device-certificates)
      - [Register Device Certificates](#register-device-certificates)
        - [Adding Tags](#adding-tags)
      - [Check Device Certificate Registration Status](#check-device-certificate-registration-status)
    - [CA Certificate Operations](#ca-certificate-operations)
    - [Flashing](#flashing)
  - [Resources](#resources)

# ESP RainMaker Admin CLI

## Introduction

ESP RainMaker Admin CLI is a tool offered by Espressif Rainmaker for admin users to be able to perform mass manufacturing of nodes of ESP32-S2 and ESP32 based products. This tool will enable you to perform node id generation and certificate registration operations required for the manufacturing process.

## Getting the Admin CLI

Clone this project using:

```
git clone https://github.com/espressif/esp-rainmaker-admin-cli.git
```

## Setup Build Environment

> **Note**: If you are using esp-idf, the python and virtual environment requirement would already be fulfilled (via install.sh), and you can just install the dependencies using `python -m pip install -r requirements.txt` and move on to the next section which speaks about the [workflow](#workflow).

### Operating System requirements
  - Linux / MacOS / Windows (standard distributions)

### Other requirements
To setup your build environment, please make sure you have the following installed on your host machine: 

  - `python` (If not installed, please refer to https://www.python.org/)
  - `pip` (If not present, please refer to https://pip.pypa.io/en/stable/)
  - `virtualenv` (You can install using command - `pip install virtualenv`). This is not mandatory, but recommended so that rest of your python based utilities do not break.

The following python versions are supported: 

- python 3.5.x
- python 3.6.x
- python 3.7.x
- python 3.8.x

### Installing dependencies

Once python and pip are installed, set up the virtual environment by following the instructions [here](https://docs.python.org/3/library/venv.html). Thereafter, please enter the directory where this tool is installed (using terminal) and execute the below to install the dependencies:

```
pip install -r requirements.txt
```

OR

```
python -m pip install -r requirements.txt
```

## Workflow

You need to perform the following steps to generate and register node credentials.
To know more about the commands in detail, please refer the Usage section below.  

1. Set Server Configuration:  
`python rainmaker_admin_cli.py account serverconfig --endpoint <endpoint>`
2. Login:  
`python rainmaker_admin_cli.py account login --email <email_id>`
3. Generate Device Certificate(s):
`python rainmaker_admin_cli.py certs devicecert generate --count <count>`
4. Register Generated Device Certificate(s):  
`python rainmaker_admin_cli.py certs devicecert register --inputfile <inputfile>`
5. Check Device Certificate Registration Status:   
`python rainmaker_admin_cli.py certs devicecert getcertstatus --requestid <request_id>`

## Usage

To get help information for any RainMaker Admin CLI command or sub-command, you can use the -h option at various levels

Eg.

```
python rainmaker_admin_cli.py -h
python rainmaker_admin_cli.py account -h
python rainmaker_admin_cli.py account login -h
```

The Admin CLI commands are divided into 2 broad categories

1. Account Operations
2. Certificate Operations

**You need to setup the account before you can move on to the Certificate Operations**


### Account Operations

#### Server Config

You need to setup server configuration to get started. The endpoint would be your deployment's Base URL of the form `https://xxxx/amazonaws.com/dev` which you would have received on the super admin email configured during RainMaker deployment.


Usage:

`python rainmaker_admin_cli.py account serverconfig --endpoint <endpoint>`

#### Login

You need to login to get started and use the subsequent APIs. The email id for login would be the super admin user email configured during RainMaker deployment. The password should have been already received on that email at the end of the backend deployment process.


Usage:
  
`python rainmaker_admin_cli.py account login --email <emailid>`

> **Note**: Login configuration will be stored at location `~/.espressif/rainmaker/rainmaker_admin_config.json`


**You can now use the rest of the commands once you have logged in successfully.**


### Device Certificate Operations

You can perform the following operations for the device certificate.

- `generate` - You can generate multiple device certificates at a time.  
- `register` - You can register multiple generated device certificates.  
- `getcertstatus` - Once you register the device certificates, you can check the device certificate registration status.

#### Generate Device Certificates

This will generate the private keys and certificates required by the RainMaker nodes to connect to your deployment. It will also set other information like the node ids, mqtt endpoint, etc.

> Notes:
>
> 1. This will also create the CA key and certificate that would be used for signing the device certificates. If you already have your own CA key and certificate, you can provide it explicitly.
> 2. The created CA certificate and key will also be stored in a common folder named - 'ca_certificates' in the current working directory for reusing them for further device certificate generation. The key and the certificate will be stored in a sub folder under 'ca_certificates' named by the mqtt endpoint as prefix.
> 3. If you want the Provisioning QR codes to be generated as well, please use the --prov option, and pass appropriate transport. Generally, the default is "ble" for all chips that support BLE (ESP32, ESP32-C3) and "softap" for the ones that do not (ESP32-S2). However, this primarily depends on what you have used in your firmware.

Usage:

```
python rainmaker_admin_cli.py certs devicecert generate [-h] [--outdir <outdir>] [--count <count>]
                                                        [--cacertfile <cacertfile>] [--cakeyfile <cakeyfile>]
                                                        [--prov <prov_type>] [--prov_prefix <prov_prefix>] [--fileid <fileid>]
                                                        [--local] [--inputfile <inputfile>] [--prefix_num <start> <length>]

optional arguments:
  -h, --help            show this help message and exit
  --outdir <outdir>     Path to output directory. Files generated will be saved in <outdir>
                        If directory does not exist, it will be created
                        Default: current directory
  --count <count>       Number of Node Ids for generating certificates
                        Default: 0
  --cacertfile <cacertfile>
                        Path to file containing CA Certificate
  --cakeyfile <cakeyfile>
                        Path to file containing CA Private Key
  --prov <prov_type>    Provisioning type to generate QR code 
                        (softap/ble) Default value: ble
  --prov_prefix <prov_prefix>    
                        Provisioning name (requires changes in firmware) Default is PROV
  --fileid <fileid>     File identifier 
                        Used to identify file for each node uniquely (used as filename suffix)
                        Default: <node_id> (The node id's generated)
                        If provided, eg. `mac_addr`(MAC address),
                        must be part of ADDITIONAL_VALUES file (provided in config)
                        and must have <count> values in the file (for each node)
  --local       This is to determine whether or not to generate node ids locally.
                        Default: false if not specified.
  --inputfile <csvfile> This is the node_ids.csv file containing pre-generated node ids.
  --prefix_num <start> <length> 
                        These prefix numbers start (counter) and length (minimum length of digits as prefix) are added for each node specific output filenames as index. For example --prefix 1 4 will set file or folder name prefixes as node-0001-<node_id>.<file_extension if it is a file>. The prefixes follow order of 0001, 0002, 0003, etc as per the start (counter) value and the number of nodes for which to generate the device certificates (--count). The default value of the index is 1 (start) and 6 (length).
```

For generating the node Ids locally without the rainmaker login:
`python rainmaker_admin_cli.py certs devicecert generate --count 5 --prov ble --outdir test --local`

For generating the node certificates by providing pre-generated node ids csv file:
`python rainmaker_admin_cli.py certs devicecert generate --count 5 --prov ble --outdir test --local --inputfile <node_ids.csv>`
> Note that in this command, count and local argument will be ignored and inputfile will get the precendence.
> - The input file must be a CSV with a header row (field names as the first row). 
> - Node IDs will only be retrieved from rows under a single column named **`node_id`**.

For simplest use case, the usage is as given below. If you want to add some custom data or customise some other parameters, please refer the subsequent sections.

> Note that it is better to first create a small set of certificates, say 5, so that you get an idea about how the tool works.

Example:
`python rainmaker_admin_cli.py certs devicecert generate --count 5 --prov ble --outdir test --local --inputfile <node_ids.csv>`

Sample result for 2 nodes is as below :

      test
      └── 2024-09-29
          └── Mfg-000001
              ├── bin
              │   ├── node-000001-T2uNDXPMS9nj9vpKjs2QG8.bin
              │   └── node-000002-dRagJ6GBim2HE5ENQ5nbYG.bin
              ├── common
              │   ├── ca.crt
              │   ├── ca.key
              │   ├── config_tmp.csv
              │   ├── config.csv
              │   ├── endpoint.txt
              │   ├── node_certs.csv
              │   ├── node_ids.csv
              │   ├── values_tmp.csv
              │   └── values.csv
              ├── csv
              │   ├── node-000001-T2uNDXPMS9nj9vpKjs2QG8.csv
              │   └── node-000002-dRagJ6GBim2HE5ENQ5nbYG.csv
              ├── node_details
              │   ├── node-000001-T2uNDXPMS9nj9vpKjs2QG8
              │   │   ├── node.crt
              │   │   ├── node.key
              │   │   ├── qrcode.txt
              │   │   └── random.txt
              │   └── node-000002-dRagJ6GBim2HE5ENQ5nbYG
              │       ├── node.crt
              │       ├── node.key
              │       ├── qrcode.txt
              │       └── random.txt
              └── qrcode
                  ├── node-000001-T2uNDXPMS9nj9vpKjs2QG8.png
                  └── node-000002-dRagJ6GBim2HE5ENQ5nbYG.png

The output directory will have the following sub-directory structure:

- `<outdir>/<current_date>/Mfg-<no>`
	- Sub-directory with the current date is created.
  	- A `Mfg-<no>` sub-directory will be created where `<no>` is the batch number (which increments on each CLI run).

The output directory contains the following files:

- `bin/`: For each device certificate, the corresponding NVS partition binaries are generated in this directory, which can be used to flash onto the device. File format: `node-<index>-<node_id>.bin`
- `common/`: This has some common files that are generated during the process
	- `ca.crt`: CA Certificate.
	- `ca.key`: CA Key.
	- `endpoint.txt`: MQTT Endpoint for this deployment.
	- `node_certs.csv` : CSV for all the Node Certificates in this batch to be registered to the cloud.
	- `node_ids.csv` : CSV for all node ids generated in this batch.
	- `config.csv` : The NVS configuration file as per the format defined [here](https://github.com/espressif/esp-idf/tree/master/tools/mass_mfg#csv-configuration-file) for the IDF Manufacturing Utility.
	- `values.csv` : Master file with all the values for all the nodes as per the format defined [here](https://github.com/espressif/esp-idf/tree/master/tools/mass_mfg#master-value-csv-file) for the IDF Manufacturing Utility.
  - The will be few '_tmp' files generated for values.csv and config.csv which will be used for internal purposes.
- `csv/`:
  - `node-<index>-<node_id>.bin`: For each device certificate, the corresponding csv file used as configuration to generate the binary.
- `keys/`:
  - `keys-node-<index>-<node_id>.bin`: For each device certificate, the corresponding encryption key (if encryption is enabled in [config](config/binary_config.ini)).the binary.
- `node_details/`: All node details are stored in this directory.   
   Following details for each node are stored in `node_details/node-<index>-<node_id>` directory:
	- `node.crt`: Device Certificates.
	- `node.key`: Private key for each device certificate.
	- `qrcode.txt`: The QR code payload (used during provisioning, available only if --prov is given).
	- `random.txt`: The random bytes information (used to generate device name and PoP, available only if --prov is given).

- `qrcode/`: QR code images for all nodes are stored in this directory (used during provisioning, available only if --prov is given). File format: `node-<index>-<node_id>.png`

**Adding Custom Data**

There could often be a requirement to add some custom data to the nvs binaries generated. Such custom data can be added using the formats specified by the ESP IDF [Manufacturing Utility](https://github.com/espressif/esp-idf/tree/master/tools/mass_mfg). The [config file](https://github.com/espressif/esp-idf/tree/master/tools/mass_mfg#csv-configuration-file) and [values file](https://github.com/espressif/esp-idf/tree/master/tools/mass_mfg#master-value-csv-file) can be given as input by setting the `ADDITIONAL_CONFIG` and `ADDITIONAL_VALUES` fields in [config/binary_config.ini](config/binary_config.ini). Please check out samples for such files at [samples/extra_config.csv](samples/extra_config.csv) and [samples/extra_values.csv](samples/extra_values.csv)
       
#### Register Device Certificates

Once the device certificates are generated, they also need to be registered with the cloud service using the register command.

Usage:

```sh
python rainmaker_admin_cli.py certs devicecert register [-h] --inputfile <csvfilename>
                                                        [--groupname <nodegroupname>] [--type <nodetype>]
                                                        [--model <nodemodel>] [--parent_groupname <parent_groupname>][--subtype <nodesubtype>]
                                                        [--tags <nodetags>]
                                                        [--force]
                                                        [--update_nodes]

optional arguments:
  -h, --help            show this help message and exit
  --inputfile <csvfilename>
                        Name of file containing node ids and certs
  --groupname <nodegroupname>
                        Name of the group to which node are to be added after successful registration
  --type <nodetype>     Node type
  --model <nodemodel>   Node model
  --parent_groupname <parent_groupname> 
                        Name of the parent group to which this newly created group will be a child group      
  --subtype <nodesubtype> Node SubType
  --tags <nodetags> Comma separated strings of tags to be attached to the nodes.(eg: location:Pune,office:espressif)
  --force  Whether to ignore the error for duplicate node registration, also updates the existing certificates
  --update_nodes Whether to skip registration of the device certificates and only add the type, model, subtype and tags to the nodes.
  --update_nodes and --force If both are given, only the existing nodes will be updated with the new type, model, subtype and tags, Also the certificates will be updated.New nodes will be skipped.
```

For the example in device certificate generation section the node_certs_file file would be `test/2020-11-29/Mfg-00001/common/node_certs.csv`.
This command will give a request id in response, which can be used for monitoring the status.

##### Adding Tags

Basic Tags can be added to nodes using the `--tags` option. Using `--tags loc:Amsterdam` will add this same tag to all the nodes in `node_certs.csv`.  
> Note that for adding tags, minimum rainmaker supported version is 1.1.27.  

If different tag values are to be used for each node in the `node_certs.csv` file, use `--tags loc:@city`, where `city` should be a column in the `node_certs.csv`.

For example:  
node_certs.csv:
| node_id | certs | city      |
| ------- | ----- | --------- |
| node1   | cert1 | Amsterdam |
| node2   | cert2 | Barcelona |

After passing `--tags loc:@city`,

- node1 will get the tag: `loc:Amsterdam`.
- node2 will get the tag: `loc:Barcelona`.

> To use CSV based tags, i.e `city:@loc` where *loc* is a column in the CSV, the minimum rainmaker supported version is 1.1.28.

#### Check Device Certificate Registration Status

The certificate registration process can take significant time. Once it is finished, the super admin user will get an email with the status. The same can also be checked using the `getcertstatus` command.

Usage:

```
python rainmaker_admin_cli.py certs devicecert getcertstatus --requestid XXXXXXX
```

Please check the output of the register command above to get the request id.


### CA Certificate Operations

The steps here would generally not be required. However, if you want to explicitly create a new CA certificate and use it for signing the device certificates, you can use this command.

Usage:

```
python rainmaker_admin_cli.py certs cacert generate
```

This will generate the CA key and certificate at following locations:

- `ca_certificates/<mqttendpoint>/ca.key` 
- `ca_certificates/<mqttendpoint>/ca.crt`

```
python rainmaker_admin_cli.py certs cacert generate --outdir <outdir>
```
This will generate the CA key and certificate at following locations:

- `<outdir>/ca.key` 
- `<outdir>/ca.crt`

If there already exists CA a certificate and a key, then the existing ones are reused.

These can be used for signing the device certificates by passing these via the `--cacertfile` and `--cakeyfile` options for `rainmaker_admin_cli.py certs devicecert generate`



### Flashing

To flash binary generated onto the device, you can use the following command:

```
esptool.py --port <port> write_flash <fctry_address> <outdir>/bin/<filename>.bin
```

> Note: The `<fctry_address>` is typically 0x340000. However, please check your partition table to find the appropriate address.
>
> The esptool.py would be available in your PATH only if you have esp-idf set up, else, please find it at `esp-idf/components/esptool_py/esptool/esptool.py` and use from there.


## Resources

* Please get in touch with your ESP RainMaker contact in case of any issues or send an email to esp-rainmaker-support@espressif.com
