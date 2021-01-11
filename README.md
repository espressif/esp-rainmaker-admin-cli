- [**ESP RainMaker Admin CLI**](#esp-rainmaker-admin-cli)
- [**Introduction**](#introduction)
- [**Setup Build Environment**](#setup-build-environment)
- [**Workflow**](#workflow)
- [**Usage**](#usage)
- [**Account Operations**](#account-operations)
- [**Certs Operations**](#certs-operations)
- [**Resources**](#resources)

# **ESP RainMaker Admin CLI**

**Introduction**
===================

ESP RainMaker Admin CLI is a tool offered by Espressif Rainmaker for admin users to be able to perform mass manufacturing of nodes of ESP32-S2 and ESP32 based products. This tool will enable you to perform node id generation and certificate registration operations required for the manufacturing process.

**Setup Build Environment**
==============================

Operating System requirements:
  - Linux / MacOS / Windows (standard distributions)

To setup your build environment, please make sure you have the following installed on your host machine: 
  - `python`   
    (To install a specific python version please refer to the OS specific environment setup given below)
  - `pip`    
    (If not present, please refer to https://pip.pypa.io/en/stable/)
  - `virtualenv`   
    (You can install using command - `pip install virtualenv`)

The following python versions are supported: 
* python 2.7.x
* python 3.5.x
* python 3.6.x
* python 3.7.x
* python 3.8.x

**OS specific environment setup**

>To setup environment for *MacOS*:
1. Python setup:  
    To install specific version please refer to https://www.python.org/downloads/  
    Use your OS specific installer to install. Follow the default installation steps.     
    Once installed, you should see the python version `<version>` installed in the following directory: 
      `/Library/Frameworks/Python.framework/Versions/<version>`
2. Go to directory where this CLI is present.
3. To create virtualenv, run command: `virtualenv -p <python_version_path> venv1`

      `<python_version_path>` for MacOS is: `/Library/Frameworks/Python.framework/Versions/<version>/Resources/Python.app/Contents/MacOS/Python`
4. Run command to activate virtualenv: `source venv1/bin/activate`
5. To install package requirements, run command `pip install -r requirements.txt`
6. Once all packages are installed successfuly (you can verify using command - `pip list`), you can start using the CLI.
7. To deactivate your virtualenv, run command `deactivate`

>To setup environment for *Linux*:
1. Python setup:  
    To install specific version please refer to https://www.python.org/downloads/  
    Use your OS specific installer to install. Follow the default installation steps.     
    Once downloaded, untar the file.
    Run the following commands to install:
      - cd <untar_dir>
      - ./configure --enable-optimizations
      - make install  
   You should see the python version `<version>` installed in the following directory: 
      `/usr/local/bin/<version>`

2. Go to directory where this CLI is present.
3. To create virtualenv, run command: `virtualenv -p <python_version_path> venv1`
   
      To know your `<python_version_path>` for Linux, run command `which python<version>`  
      for eg. `which python3.7`, the output of the command is your `<python_version_path>`
4. Run command to activate virtualenv: `source venv1/bin/activate`
5. To install package requirements, run command `pip install -r requirements.txt`
6. Once all packages are installed successfuly (you can verify using command - `pip list`), you can start using the CLI.
7. To deactivate your virtualenv, run command `deactivate`.

>To setup environment for *Windows*:
1. Python setup:  
    To install specific version please refer to https://www.python.org/downloads/  
    Use your OS specific installer to install. Follow the default installation steps.     
    Once installed, you should see the python version `<version>` installed in the following directory:   
      `C:\Users\<user>\AppData\Local\Programs\Python\<version>`  
         **Note:** If you already have python2.7 installed, you may find it in path `C:\<version>`

2. Go to directory where this CLI is present.
3. To create virtualenv, run command: `virtualenv -p <python_version_path> venv1`
   
      `<python_version_path>` for Windows is: `C:\Users\<user>\AppData\Local\Programs\Python\<version>\python.exe`  
         **Note:** For pre-installed python2.7, `<python_version_path>` will be `C:\<version>\python.exe`
4. Run command to activate virtualenv: `\path\to\env\Scripts\activate.bat`
5. To install package requirements, 
   1. If you are using python version==2.7, please run commands in the following order:
      - `pip install pyopenssl`
      - `pip install -r requirements.txt`
   2. If you are using any other python version, please run only the following command:
      - `pip install -r requirements.txt`
6. Once all packages are installed successfuly, you can start using the CLI.
7. To deactivate your virtualenv, run command `deactivate`.

----------

**Workflow**
=============

You need to perform the following steps to use the Node Manufacturing Tool.  
To know more about the commands, please refer to the Usage section below.  

> 1. Set Server Configuration using command:  
> `python rainmaker_admin_cli.py account serverconfig --endpoint <endpoint>`
> 2. Login using command:  
> `python rainmaker_admin_cli.py account login --email <email_id>`
> 3. Generate Device Certificate(s) using command:
> `python rainmaker_admin_cli.py certs devicecert generate --count <count>`
> 4. Register Generated Device Certificate(s) using command:  
> `python rainmaker_admin_cli.py certs devicecert register --inputfile <inputfile>`
> 5. Check Device Certificate Registration Status using command:   
> `python rainmaker_admin_cli.py certs devicecert getcertstatus --requestid <request_id>`

**Usage**
============

You can perform the following operations using the CLI.

        usage: rainmaker_admin_cli.py [-h] {account,certs} ...

        ESP Rainmaker Admin CLI

        optional arguments:
        -h, --help       show this help message and exit

        Commands:
        {account,certs}  usage: rainmaker_admin_cli.py {command} -h for additional help
        account          Account Operations
        certs            Certificate Operations

**You need to set your server configuration and account configuration first in order to perform the manufacturing CLI operations. The CLI tool provides the *Account Operations* for the same.**

**Account Operations**
=======================
        usage: rainmaker_admin_cli.py account [-h] {serverconfig,login} ...

        optional arguments:
        -h, --help            show this help message and exit

        Commands:
        {serverconfig,login}
        serverconfig        Generate server configuration
        login               Login using registered email-id

   > **Set Server Config**
   > ---------------------------

   You need to setup server configuration to get started.

>        usage: rainmaker_admin_cli.py account serverconfig [-h]
>                                                        [--endpoint <endpoint>]
>
>        optional arguments:
>        -h, --help            show this help message and exit
>        --endpoint <endpoint>
>                                Server endpoint to use for CLI Operations
>
> **Example:**  
> `python rainmaker_admin_cli.py account serverconfig --endpoint https://xxx/v0/`

   > **Login**
   > -------------------
   You need to login to get started.

>        usage: rainmaker_admin_cli.py account login [-h] [--email <emailid>]
>
>        optional arguments:
>        -h, --help         show this help message and exit
>        --email <emailid>  Registered email-id to login
>
> **Example:**   
> `python rainmaker_admin_cli.py account login --email abc@xyz.com`

**Note:** Login configuration will be stored at location `~/.espressif/rainmaker/rainmaker_admin_config.json`

---------------

**You can now perform manufacturing CLI operations once you have logged in successfully.**

-------------------

**Certs Operations**
=======================
        usage: rainmaker_admin_cli.py certs [-h] {cacert,devicecert} ...

        optional arguments:
        -h, --help           show this help message and exit

        Commands:
        {cacert,devicecert}
        cacert             CA Certificate Operations
        devicecert         Device Certificate Operations

> **Device Certificate Operations**
> ----------------------------------
You can perform the following operations on the device certificate.

- `generate` - You can generate multiple device certificates at a time.  
- `register` - You can register multiple generated device certificates.  
- `getcertstatus` - Once you register the device certificates, you can check the device certificate registration status.

        usage: rainmaker_admin_cli.py certs devicecert [-h]
                                                {generate,register,getcertstatus}
                                                ...

        optional arguments:
        -h, --help            show this help message and exit

        Commands:
        {generate,register,getcertstatus}
        generate            Generate device certificate(s)
        register            Register device certificate(s)
        getcertstatus       Check Device Certificate Registration Status

> **Generate Device Certificate** 
> --------------------------------
>         usage: rainmaker_admin_cli.py certs devicecert generate [-h]
>                                                               [--outdir <outdir>]
>                                                               [--count <count>]
>                                                               [--cacertfile <cacertfile>]
>                                                               [--cakeyfile <cakeyfile>]
>                                                               [--prov <prov_type>]
>                                                               [--fileid <fileid>]
>
>         optional arguments:
>         -h, --help            show this help message and exit
>         --outdir <outdir>     Path to output directory. Files generated will be saved in <outdir>
>                                 If directory does not exist, it will be created
>                                 Default: current directory
>         --count <count>       Number of Node Ids for generating certificates
>                                 Default: 0
>         --cacertfile <cacertfile>
>                                 Path to file containing CA Certificate
>         --cakeyfile <cakeyfile>
>                                 Path to file containing CA Private Key
>         --prov <prov_type>    Provisioning type to generate QR code
>                                 (softap/ble)
>         --fileid <fileid>     File identifier
>                                 Used to identify file for each node uniquely
>                                 Default: <node_id> (The node id's generated)
>                                 If provided, eg. `mac_addr`(MAC address),
>                                 must be part of ADDITIONAL_VALUES file (provided in config)
>                                 and must have <count> values in the file (for each node)
>
> **Example:**   
> `python rainmaker_admin_cli.py certs devicecert generate --count 2 --outdir test`
**Note**: This command will also generate CA Certificate required for device certificates.

This command will generate the following files in `test` (`<outdir>`) directory:

      test
      └── 2020-11-29
         └── Mfg-00001
            ├── bin
            │   ├── node-00001-T2uNDXPMS9nj9vpKjs2QG8.bin
            │   └── node-00002-dRagJ6GBim2HE5ENQ5nbYG.bin
            ├── common
            │   ├── ca.crt
            │   ├── ca.key
            │   ├── config.csv
            │   ├── endpoint.txt
            │   ├── node_certs.csv
            │   ├── node_ids.csv
            │   └── values.csv
            ├── node_details
            │   ├── node-00001-T2uNDXPMS9nj9vpKjs2QG8
            │   │   ├── node.crt
            │   │   ├── node.key
            │   │   ├── node_info.csv
            │   │   ├── qrcode.txt
            │   │   └── random.txt
            │   └── node-00002-dRagJ6GBim2HE5ENQ5nbYG
            │       ├── node.crt
            │       ├── node.key
            │       ├── node_info.csv
            │       ├── qrcode.txt
            │       └── random.txt
            └── qrcode
                  ├── node-00001-T2uNDXPMS9nj9vpKjs2QG8.png
                  └── node-00002-dRagJ6GBim2HE5ENQ5nbYG.png

The output directory will create the following sub-directory structure:  
- `<outdir>/<current_date>/Mfg-<no>`: 
  - Sub-directory with the current date is created.
  - Each CLI command run for generating a device certificates batch, a `Mfg-<no>` sub-directory will be created where `<no>` is the number corresponding to the CLI run, `Mfg-00001` in this case. 

The output directory contains the following files:
1. `bin/`: For each device certificate, the corresponding NVS partition binaries are generated in this directory, which can be used to flash onto the device.
                File format: `node-<index>-<node_id>.bin`
        
     - You can set the input parameters to generate the binary in the config file provided here: `config/binary_config.ini`
     - You can provide `ADDITIONAL_CONFIG` and `ADDITIONAL_VALUES` file in the config.
       - The format for `ADDITIONAL_CONFIG` file should be same as the `common/config.csv` file generated.
       - The format for `ADDITIONAL_VALUES` file should be same as the `common/values.csv` file generated.
       - This `ADDITIONAL_CONFIG` and `ADDITIONAL_VALUES` file contents will be part of the final binary generated.

      **Note:** Sample files are provided in `samples/` directory.
     
     **Note:** The following dependent common files are generated in `common/` directory:
      - `common/config.csv`  
      - `common/values.csv`
      - `common/endpoint.txt`
      - `common/node_certs.csv`
      - `common/node_ids.csv`

2. `node_details/`: All node details are stored in this directory.   
   Following details for each node are stored in `node_details/node-<index>-<node_id>` directory:
      1. Device Certificates: `node.crt`
      2. Private key for each device certificate: `node.key`
      3. The master csv file used as configuration to generate the binary: `node_info.csv`
      4. The QR code payload (used during provisioning): `qrcode.txt`
      5. The random string information (used as PoP): `random.txt`
      6. Encryption key (if encryption is enabled in config): `node_encr_key.bin`

3. `test/qrcode/`: QR code images (used during provisioning) for all nodes is stored in this directory.
                   File format: `node-<index>-<node_id>.png`

> **Example:**   
> `python rainmaker_admin_cli.py certs devicecert generate --count 2 --outdir test --cacertfile test2/ca_cert.crt --cakeyfile test2/ca_key.key`

- Alongwith the output directory contents as mentioned above, this command will copy `--cacertfile` to `<outdir>/<current_date>/Mfg-<no>/common/ca.crt` and `--cakeyfile` to `<outdir>/<current_date>/Mfg-<no>/common/ca.key`.   
 So, `test2/ca_cert.crt` is copied to `test/2020-11-29/Mfg-00001/common/ca.crt` and `test2/ca_key.key` is copied to `test/2020-11-29/Mfg-00001/common/ca.key`. 


**Note**: If you wish to generate CA Certificate separately, the following command is also provided.
> **CA Certificate Operations**
> ------------------------------
You can generate CA Certificate on the host.
> 3. Generate CA Certificate (if you do not have a CA Certificate generated on your host)  
> `python rainmaker_admin_cli.py certs cacert generate`
>        usage: rainmaker_admin_cli.py certs cacert generate [-h] [--outdir <outdir>]
>
>        optional arguments:
>        -h, --help         show this help message and exit
>        --outdir <outdir>  Path to output directory. Files generated will be saved in <outdir>
>                           If directory does not exist, it will be created
>                           Default: current directory
>                           Certificate Filename: ca.crt
>                           Key Filename: ca.key
>
> **Example:**  
> `python rainmaker_admin_cli.py certs cacert generate --outdir test`

Output files will be generated in *test* directory:

      test/
      └── 2020-11-29
         └── Mfg-00001
             └── common
                 └── ca.crt
                 └── ca.key

This command will generate the following files in `test` (`<outdir>`) directory:
   1. `test/<current_date>/Mfg-<no>/common/ca.crt`: CA Certificate generated is stored in this file.  
      `test/<current_date>/Mfg-<no>/common/ca.key`: Alongwith CA Certificate, CA Key is also generated. 

> **Register Device Certificate**  
> --------------------------------  
>
>        usage: rainmaker_admin_cli.py certs devicecert register [-h]
>                                                                [--inputfile <csvfilename>]
>
>        optional arguments:
>        -h, --help            show this help message and exit
>        --inputfile <csvfilename>
>                                Name of file containing node ids and certs
>
> **Example:**  
> `python rainmaker_admin_cli.py certs devicecert register --inputfile test/node_certs_20-08-05_12-40-41.csv`

> **Check Device Certificate Registration Status**   
> ------------------------------------------------- 
>
>        usage: rainmaker_admin_cli.py certs devicecert getcertstatus
>        [-h] [--requestid <requestid>]
>
>        optional arguments:
>        -h, --help            show this help message and exit
>        --requestid <requestid>
>                                Request Id of device certificate registration
>
> **Example:**  
> `python rainmaker_admin_cli.py certs devicecert getcertstatus --requestid XXXXXXX`

> **Flash Binary Onto Device**   
> ------------------------------------------------- 
>
> To flash binary generated onto the device, you can use the following command:
> 
> python esptool.py --port \<port\> write_flash 0x340000 \<outdir\>/bin/\<filename\>.bin`

------------

**Resources**
================

* Please get in touch with your ESP RainMaker contact in case of any issues or send an email to esp-rainmaker-support@espressif.com