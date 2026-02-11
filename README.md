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
      - [Logout](#logout)
    - [Device Certificate Operations](#device-certificate-operations)
      - [Generate Device Certificates](#generate-device-certificates)
      - [Register Device Certificates](#register-device-certificates)
        - [Adding Tags](#adding-tags)
      - [Check Device Certificate Registration Status](#check-device-certificate-registration-status)
    - [CA Certificate Operations](#ca-certificate-operations)
    - [Flashing](#flashing)
    - [Download API Response](#download-api-response)
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
`python rainmaker_admin_cli.py certs devicecert generate [--videostream] [--no-pop] [--encryption <true|false>] --count <count>`
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

The Admin CLI uses a **profile-based system** to manage multiple server configurations. Each profile can have its own server endpoint and login credentials, allowing you to easily switch between different RainMaker deployments (e.g., development, staging, production).

#### Server Config

You need to setup server configuration to get started. The endpoint would be your deployment's Base URL of the form `https://xxxx/amazonaws.com/dev` which you would have received on the super admin email configured during RainMaker deployment.

When you run `serverconfig` for the first time, it creates a profile named `default` with the specified endpoint. You can create additional profiles using the `account profile add` command.

Usage:

`python rainmaker_admin_cli.py account serverconfig --endpoint <endpoint> [--profile <profile_name>]`

Optional arguments:
- `--profile <profile_name>`: Profile name to use (defaults to 'default'). If the profile doesn't exist, it will be created.

#### Profile Management

Profiles allow you to manage multiple server configurations and switch between them. Each profile stores its own server endpoint and login credentials separately.

##### List Profiles

List all available profiles and see which one is currently active.

Usage:

`python rainmaker_admin_cli.py account profile list`

This command displays:
- All available profiles
- Which profile is currently active (marked with "(current)")
- Description and base URL for each profile
- Login status for each profile

##### Show Current Profile

Display information about the currently active profile.

Usage:

`python rainmaker_admin_cli.py account profile current`

This command shows:
- Current profile name
- Profile description
- Base URL configuration
- Login status

##### Switch Profile

Switch to a different profile. This changes the active profile for subsequent CLI operations.

Usage:

`python rainmaker_admin_cli.py account profile switch <profile_name>`

> **Note**: After switching profiles, you may need to login again if the new profile doesn't have stored credentials.

##### Add Profile

Create a new custom profile with a specific base URL. This is useful for managing multiple RainMaker deployments.

Usage:

`python rainmaker_admin_cli.py account profile add <profile_name> --base-url <base_url> [--description <description>]`

Arguments:
- `<profile_name>`: Name of the profile to create
- `--base-url <base_url>`: Base URL for the profile (required)
- `--description <description>`: Optional description for the profile

Example:

`python rainmaker_admin_cli.py account profile add production --base-url https://api.rainmaker.example.com --description "Production deployment"`

> **Note**: If a profile with the same name already exists, you'll be prompted to confirm overwriting it.

##### Remove Profile

Delete a custom profile. The default profile cannot be deleted.

Usage:

`python rainmaker_admin_cli.py account profile remove <profile_name>`

Arguments:
- `<profile_name>`: Name of the profile to remove

> **Note**: You'll be prompted to confirm before deletion. If you delete the currently active profile, the CLI will automatically switch to the default profile.

#### Login

You need to login to get started and use the subsequent APIs. The email id for login would be the super admin user email configured during RainMaker deployment. The password should have been already received on that email at the end of the backend deployment process.

Login credentials are stored per profile, so you can have different credentials for different deployments.

Usage:

`python rainmaker_admin_cli.py account login --email <emailid> [--password <password>]`

> **Note**: If password is not passed, it will be prompted for and not shown on screen for security reasons.

> **Note**: Login configuration is stored per profile at location `~/.espressif/rainmaker/admin_profiles/`

#### Logout

To logout from the current session and clear stored credentials for the active profile.

Usage:

`python rainmaker_admin_cli.py account logout`

> **Note**: This will logout from the server and remove local session data for the current profile only. Other profiles' credentials remain unaffected.


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
                                                        [--cloud] [--local] [--inputfile <inputfile>] [--prefix_num <start> <length>]
                                                        [--videostream] [--no-pop] 
                                                        [--encryption <true|false>] [--key_type <key_type>]

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
  --cloud               Use cloud-based node ID generation.
                        Default: local generation is used if not specified.
  --local               Use local node ID generation (default behavior).
                        This flag is redundant but kept for compatibility.
  --inputfile <csvfile> This is the node_ids.csv file containing pre-generated node ids.
  --prefix_num <start> <length>
                        These prefix numbers start (counter) and length (minimum length of digits as prefix) are added for each node specific output filenames as index. For example --prefix_num 1 4 will set file or folder name prefixes as node-0001-<node_id>.<file_extension if it is a file>. The prefixes follow order of 0001, 0002, 0003, etc as per the start (counter) value and the number of nodes for which to generate the device certificates (--count). The default value of the index is 1 (start) and 6 (length).
  --videostream         Require mqtt_cred_host to be present in the response. Will throw an error if not available.
  --no-pop              Generate QR code without pop field. When specified, the QR code payload will not include the 'pop' field.
  --encryption <true|false>   This can be used to generate encrypted nvs binaries for additional security (Requires appropriate support to be enabled in firmware. Overrides ENCR_ENABLED from config/binary_config.ini).
  --key_type <key_type> Cryptographic key type for device certificates. Options: 'rsa' (RSA 2048-bit, default) or 'ecdsa' (ECDSA P-256, faster and smaller).
```

For generating the node Ids locally without the rainmaker login:
`python rainmaker_admin_cli.py certs devicecert generate --count 5 --prov ble --outdir test --local`

For generating the node certificates by providing pre-generated node ids csv file:
`python rainmaker_admin_cli.py certs devicecert generate --prov ble --outdir test --inputfile <node_ids.csv>`
> Note: In this command, the count and local arguments will be ignored, and the inputfile will take precedence, determining the number of Node IDs for which device certificates will be generated.
> - The input file must be a CSV with a header row (field names as the first row).
> - Node IDs will only be retrieved from rows under a single column named **`node_id`**.

For generating device certificates with QR codes without the pop field:
`python rainmaker_admin_cli.py certs devicecert generate --count 5 --prov ble --outdir test --no-pop`
> Note: When using `--no-pop`, the generated QR codes will not include the pop field, which might be required for certain firmware implementations that don't use pop-based authentication.

For generating device certificates with encryption enabled for binary generation:
`python rainmaker_admin_cli.py certs devicecert generate --count 5 --prov ble --outdir test --encryption true`

For generating device certificates with ECDSA keys (faster, smaller certificates):
`python rainmaker_admin_cli.py certs devicecert generate --count 100 --key_type ecdsa --outdir test`
> Note: ECDSA P-256 certificates are faster to generate and smaller in size compared to RSA, while providing equivalent security. RSA remains the default for compatibility.

For simplest use case, the usage is as given below. If you want to add some custom data or customise some other parameters, please refer the subsequent sections.

> Note that it is better to first create a small set of certificates, say 5, so that you get an idea about how the tool works. A maximum of 50,000 certificates can be generated in a single request.

Example:
`python rainmaker_admin_cli.py certs devicecert generate --count 5 --prov ble --outdir test`

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
              │   ├── mqtt_cred_host.txt  # if --videostream option was given
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
  - `mqtt_cred_host.txt`: Endpoint to obtain credentials for webrtc video streaming
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

> **Note:**
> - When a valid values CSV file is specified in the `ADDITIONAL_VALUES` field, the `--count` argument is ignored, and the number of Node Ids for generating certificates is determined by the number of rows (excluding the header) in the provided CSV file.
> - If a `node_ids.csv` file is provided via the `--inputfile` argument, the row count from the `ADDITIONAL_VALUES` CSV file is ignored, and the node count is determined by the `node_ids.csv` file instead.
> - The precedence for determining the node count for device certificate generation is as follows:
>   1. `node_ids.csv` file passed via `--inputfile`
>   2. Values CSV file specified in the `ADDITIONAL_VALUES` field
>   3. The `--count` argument (used only if neither of the above is provided).
> - When videostream feature is needed, `--videostream` switch should be passed to instruct the tool to include `mqtt_cred_host` in the factory partition.


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
                                                        [--node_policies <policies>]
                                                        [--skip_csv_validation]

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
  --node_policies IoT access policies that need to be attached to the manufactured nodes, eg. videostream.
  --node_policies option cannot be used together with --update_nodes. If both are provided, the command will fail.
  --node_policies valid values: 'mqtt', 'videostream', or leave empty (default: mqtt). Multiple policies can be specified as comma-separated values (e.g., 'mqtt,videostream').
  --skip_csv_validation Skip CSV validation (both certificate CN validation and column count validation). Use this option if you have want to bypass this check (NOT RECOMMENDED).
```

For the example in device certificate generation section the node_certs_file file would be `test/2020-11-29/Mfg-00001/common/node_certs.csv`.
This command will give a request id in response, which can be used for monitoring the status. A maximum of 50,000 certificates can be registered in a single request.

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
python rainmaker_admin_cli.py certs cacert generate [--key_type <key_type>]
```

This will generate the CA key and certificate at following locations:

- `ca_certificates/<mqttendpoint>/ca.key`
- `ca_certificates/<mqttendpoint>/ca.crt`

```
python rainmaker_admin_cli.py certs cacert generate --outdir <outdir> [--key_type <key_type>]
```
This will generate the CA key and certificate at following locations:

- `<outdir>/ca.key`
- `<outdir>/ca.crt`

If there already exists CA a certificate and a key, then the existing ones are reused.

The `--key_type` option allows you to choose between 'rsa' (RSA 2048-bit, default) and 'ecdsa' (ECDSA P-256) for the CA certificate. Both can sign any type of device certificate.

These can be used for signing the device certificates by passing these via the `--cacertfile` and `--cakeyfile` options for `rainmaker_admin_cli.py certs devicecert generate`



### Flashing

To flash binary generated onto the device, you can use the following command:

```
esptool.py --port <port> write_flash <fctry_address> <outdir>/bin/<filename>.bin
```

> Note: The `<fctry_address>` is typically 0x340000. However, please check your partition table to find the appropriate address.
>
> The esptool.py would be available in your PATH only if you have esp-idf set up, else, please find it at `esp-idf/components/esptool_py/esptool/esptool.py` and use from there.


### Download API Response

The `download` command allows you to fetch API responses from the RainMaker backend and save them to files. This is particularly useful for extracting paginated data (like node lists) and converting them to CSV format for analysis or reporting.

#### Purpose

- Download API responses from any RainMaker API endpoint
- Extract paginated array data and combine it into a single CSV file
- Handle pagination automatically to fetch multiple pages
- Export data for offline analysis or reporting

#### Usage

```sh
python rainmaker_admin_cli.py download --api <api> [--out <folder>] [--csv_key <key>] [--csv_columns <columns>] [--query_params <params>] [--pages <num>]
```

#### Arguments

- `--api <api>` (required): API endpoint path (e.g., `/admin/nodes`)
- `--out <folder>` (optional): Output folder name where files will be saved. Default: `downloads`
- `--csv_key <key>` (optional): Key name in JSON response to extract as CSV. The value must be an array (e.g., `node_info`). Supports nested paths using dot notation (e.g., `ts_data.params.values`). Use empty string `""` if the API response itself is directly an array (e.g., `[{...}, {...}]`). If not provided, only the API response will be saved (useful for understanding the API structure).
- `--csv_columns <columns>` (optional): Comma-separated list of column names for CSV. Supports dot notation for nested keys (e.g., `connectivity.timestamp`). Use `^` prefix to extract fields from parent context when extracting nested arrays (e.g., `^param_name` to get `param_name` from the parent object). If provided, CSV will only contain these columns in the specified order.
- `--query_params <params>` (optional): Query parameters for API request (e.g., `node_list=true&status=online`)
- `--pages <num>` (optional): Number of pages to query. Default: 1. Use `0` to query all pages until end.

#### Output Files

When the command executes, it creates a timestamped subdirectory in the output folder to organize files from each run:

```
<output_folder>/
  └── <timestamp>/
      ├── api_request.txt
      ├── api_response.txt
      └── list.csv (only created if --csv_key is provided)
```

The timestamp format is `YYYYMMDD_HHMMSS` (e.g., `20251113_105742`), ensuring each run is isolated in its own directory.

**File descriptions:**
- `api_request.txt`: Summary of the API request including URL, query parameters, CSV settings, and pagination statistics
- `api_response.txt`: Contains the complete first page API response as-is (unmodified)
- `list.csv`: Contains the extracted CSV data (only created if `--csv_key` is provided)

#### Pagination

The download command automatically handles pagination:

- **Default behavior**: Fetches only the first page (`--pages 1` or omitted)
- **Multiple pages**: Use `--pages <num>` to fetch a specific number of pages
- **All pages**: Use `--pages 0` to fetch all pages until the end
- **Pagination detection**: Stops when `next_id` is absent, `null`, or `"null"` in the response
  - For object responses: Checks top-level `next_id`, then nested locations (e.g., `array[0].next_id`)
  - **Note**: Direct array responses (root is an array) are not paginated and will only fetch a single page
- **Query params**: User-provided `--query_params` are included in all page requests
- **CSV accumulation**: When using `--csv_key`, items from all fetched pages are combined into a single CSV file

#### Examples

**Basic download (first page only, to default folder):**
```sh
python rainmaker_admin_cli.py download --api "/admin/nodes"
```

**Basic download with custom output folder:**
```sh
python rainmaker_admin_cli.py download --api "/admin/nodes" --out "my_data"
```

**Download with CSV extraction:**
```sh
python rainmaker_admin_cli.py download --api "/admin/nodes" --csv_key "node_info"
```

**Download with custom CSV columns:**
```sh
python rainmaker_admin_cli.py download --api "/admin/nodes" --csv_key "node_info" --csv_columns "node_id,node_status,registration_timestamp"
```

**Download with nested field extraction (dot notation):**
```sh
python rainmaker_admin_cli.py download --api "/admin/nodes" --csv_key "node_info" --csv_columns "node_id,status.connectivity.connected,status.connectivity.timestamp"
```

**Download with nested array extraction and parent context:**
```sh
python rainmaker_admin_cli.py download --api "/admin/nodes/simple_tsdata" --csv_key "ts_data.params.values" --csv_columns "^param_name,ts,val" --query_params "data_type=string&node_id=simple_ts_node_3&param_name=text"
```
> Note: When extracting nested arrays (e.g., `ts_data.params.values`), use `^param_name` to include fields from the parent object (`params` in this case). The `^` prefix extracts the field from the parent context, while regular column names extract from the array items themselves.

**Download when API response is directly an array:**
```sh
python rainmaker_admin_cli.py download --api "/admin/api_paths_method" --csv_key "" --csv_columns "path,methods"
```
> Note: When the API response is directly an array (e.g., `[{...}, {...}]`), use empty string `""` for `--csv_key` to extract the array directly. The response structure will be checked to ensure it's an array. **Note**: Direct array responses are not paginated and will only fetch a single page.

**Download with query parameters:**
```sh
python rainmaker_admin_cli.py download --api "/admin/nodes" --csv_key "node_info" --query_params "status=online&node_list=true"
```

**Download multiple pages:**
```sh
python rainmaker_admin_cli.py download --api "/admin/nodes" --csv_key "node_info" --pages 5
```

**Download all pages:**
```sh
python rainmaker_admin_cli.py download --api "/admin/nodes" --csv_key "node_info" --pages 0
```

**Complete example with all options:**
```sh
python rainmaker_admin_cli.py download --api "/admin/nodes" --out "nodes_export" --csv_key "node_info" --csv_columns "node_id,node_status,registration_timestamp,status.connectivity.timestamp" --query_params "status=online" --pages 0
```

#### Notes

- **Authentication**: You must be logged in to use this command (see [Login](#login))
- **Understanding API structure**: Run the command without `--csv_key` first to see the API response structure and identify which key contains the data you want to extract
- **Direct array responses**: If the API response is directly an array (e.g., `[{...}, {...}]`), use empty string `""` for `--csv_key` to extract the array directly
- **Nested array extraction**: Use dot notation in `--csv_key` to extract nested arrays (e.g., `ts_data.params.values`). Arrays in the path are automatically traversed and flattened.
- **Parent context fields**: When extracting nested arrays, use `^` prefix in `--csv_columns` to include fields from parent objects. For example, `^param_name` extracts `param_name` from the parent `params` object when extracting `values` array. The `^` prefix is stripped from the CSV header (e.g., `^param_name` appears as `param_name` in the CSV).
- **Dot notation**: Use dot notation (e.g., `status.connectivity.timestamp`) to access nested JSON fields in `--csv_columns`
- **Array handling**: Arrays and nested objects in CSV are converted to JSON string format
- **Column ordering**: If `--csv_columns` is provided, columns appear in the exact order specified. Otherwise, `node_id` is placed first (if present), followed by other columns alphabetically
- **Directory organization**: Each run creates a timestamped subdirectory with all related files grouped together


## Resources

* Please get in touch with your ESP RainMaker contact in case of any issues or send an email to esp-rainmaker-support@espressif.com
