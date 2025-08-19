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


import argparse
import os
import traceback
import rmaker_admin_cmd.cmds
from rmaker_admin_lib.exceptions import CLIError
from rmaker_admin_lib.logger import log
PATH_SEP = os.sep


class ArgParser():
    def __init__(self):
        self.description = '\nESP Rainmaker Admin CLI'
        self.formatter_class = argparse.RawTextHelpFormatter
        self.parser = None
        self.args = None
        log.debug('Initialising argparser, default parameters set: '
                  'description: {} formatter_class: {} parser: {} '
                  'args: {}'.format(
                      self.description,
                      self.formatter_class,
                      self.parser,
                      self.args))

    def setup(self, dest=''):
        '''
        CLI Setup
        '''
        try:
            # Set Parent Parser
            log.debug("Setting up argparser")
            self.parser = argparse.ArgumentParser(
                description=self.description,
                formatter_class=self.formatter_class)
            log.debug("Parent parser set")
            # Add parent subparser
            parent_subparser = self._add_subparser(
                self.parser,
                title='Commands',
                help_text='usage: rainmaker_admin_cli.py {command} -h for '
                          'additional help',
                dest=dest)
            return parent_subparser

        except KeyError as key_err:
            log.error(KeyError(str(key_err)))
            print(traceback.format_exc())
        except AttributeError as attr_err:
            log.error(AttributeError(str(attr_err)))
            print(traceback.format_exc())
        except Exception as err:
            log.error(CLIError('ERROR: Error occurred during '
                               'CLI Setup. {}'.format(err)))
            print(traceback.format_exc())
        return

    def parse_args(self):
        '''
        Parse args
        '''
        self.args = self.parser.parse_args()
        return self.args

    def set_command(self, parser, cmd, dest=None):
        '''
        Set CLI command

        :param parser: Parent parser to set command for
        :type parser: <Argparse parser>

        :param cmd: CLI Command
        :type cmd: str
        '''
        cmd_parser = self._add_parser(parser, cmd=cmd)
        cmd_subparser = self._add_subparser(
            cmd_parser,
            cmd=cmd,
            title="Commands",
            dest=dest)
        return cmd_parser, cmd_subparser

    def set_sub_command(self, subparser, subcmd):
        '''
        Set CLI sub-command

        :param subparser: Parent subparser to set sub-command for
        :type subparser: <Argparse subparser>

        :param subcmd: CLI command
        :type subcmd: str
        '''
        subcmd_parser = self._add_parser(subparser, cmd=subcmd)
        self._set_default_function(subcmd_parser, cmd=subcmd)
        self._add_argument(subcmd_parser, cmd=subcmd)

    def _set_default_function(self, parser, cmd=""):
        '''
        Set default function for parser

        :param parser: Parent parser to set command for
        :type parser: <Argparse parser>

        :param cmd: CLI Command
        :type cmd: str
        '''
        func = COMMANDS[cmd]["func"]
        func_name = getattr(rmaker_admin_cmd.cmds, func)
        parser.set_defaults(func=func_name)
        log.debug("Default function set: {}".format(func))

    def _add_subparser(self, parser, cmd="", title="", help_text="", dest=""):
        '''
        Add subparser

        :param parser: Parent parser to set command for
        :type parser: <Argparse parser>

        :param cmd: CLI Command
        :type cmd: str

        :param title: CLI Command title
        :type title: str

        :param help_text: CLI Command help text
        :type help_text: str
        '''
        log.debug("Adding subparser for cmd: {}".format(cmd))

        # Add subparser to parser
        if title or help_text:
            subparser = parser.add_subparsers(title=title,
                                              help=help_text,
                                              dest=dest)
        else:
            subparser = parser.add_subparsers(dest=dest)
        return subparser

    def _add_parser(self, subparser, cmd=""):
        '''
        Add Parser

        :param subparser: Parent subparser
        :type subparser: <Argparse subparser>

        :param cmd: CLI command
        :type cmd: str
        '''
        # Add parser to parent parser parameter passed
        log.debug("Adding parser for cmd: {}".format(cmd))
        parser = subparser.add_parser(COMMANDS[cmd]["cmd"],
                                      help=COMMANDS[cmd]["help"],
                                      formatter_class=self.formatter_class)
        return parser

    def _add_argument(self, parser, cmd=""):
        '''
        Add Argument to parser

        :param parser: Parent parser
        :type parser: <Argparse parser>

        :param cmd: CLI Command
        :type cmd: str
        '''
        # Add argument to parser parameter passed
        for arg in COMMANDS[cmd]["args"]:
            if 'choices' in arg.keys():
                parser.add_argument(arg["argname"],
                                    metavar=arg["metavar"],
                                    default=arg["default"],
                                    help=arg["arghelp"],
                                    choices=arg["choices"])
            elif 'action' in arg.keys():
                parser.add_argument(arg["argname"],
                                    default=arg["default"],
                                    help=arg["arghelp"],
                                    action=arg["action"])
            else:
                parser.add_argument(arg["argname"],
                                    metavar=arg["metavar"],
                                    nargs=arg["nargs"] if "nargs" in arg else None,
                                    default=arg["default"],
                                    help=arg["arghelp"])

COMMANDS = {
    "account": {
        "cmd": "account",
        "help": "Account Operations"
    },
    "serverconfig": {
        "cmd": "serverconfig",
        "help": "Generate server configuration\n",
        "func": "configure_server",
        "args": [
            {
                "argname": "--endpoint",
                "metavar": "<endpoint>",
                "default": "",
                "arghelp": "Server endpoint to use for CLI Operations"
            }
        ]
    },
    "login": {
        "cmd": "login",
        "help": "Login using registered email-id\n",
        "func": "login",
        "args": [
            {
                "argname": "--email",
                "metavar": "<emailid>",
                "default": "",
                "arghelp": "Registered email-id to login"
            }
        ]
    },
    "certs": {
        "cmd": "certs",
        "help": "Certificate Operations"
    },
    "cacert": {
        "cmd": "cacert",
        "help": "CA Certificate Operations\n"
    },
    "cacert_generate": {
        "cmd": "generate",
        "help": "Generate CA certificate",
        "func": "generate_ca_cert",
        "args": [
            {
                "argname": "--outdir",
                "metavar": "<outdir>",
                "default": os.getcwd(),
                "arghelp": 'Path to output directory. '
                           'Files generated will be saved in <outdir>\n'
                           'If directory does not exist, '
                           'it will be created\n'
                           'Default: current directory\n'
                           'Certificate Filename: ca.crt\n'
                           'Key Filename: ca.key\n'
            }
        ]
    },
    "devicecert": {
        "cmd": "devicecert",
        "help": "Device Certificate Operations\n"
    },
    "devicecert_generate": {
        "cmd": "generate",
        "help": "Generate device certificate(s)",
        "func": "generate_device_cert",
        "args": [
            {
                "argname": "--outdir",
                "metavar": "<outdir>",
                "default": os.getcwd(),
                "arghelp": 'Path to output directory. '
                           'Files generated will be saved in <outdir>\n'
                           'If directory does not exist, it will be created\n'
                           'Default: current directory'
            },
            {
                "argname": "--count",
                "metavar": "<count>",
                "default": "0",
                "arghelp": 'Number of Node Ids for generating certificates\n'
                           'Default: 0'
            },
            {
                "argname": "--cacertfile",
                "metavar": "<cacertfile>",
                "default": "",
                "arghelp": 'Path to file containing CA Certificate'
            },
            {
                "argname": "--cakeyfile",
                "metavar": "<cakeyfile>",
                "default": "",
                "arghelp": 'Path to file containing CA Private Key'
            },
            {
                "argname": "--prov",
                "metavar": "<prov_type>",
                "default": "ble",
                "arghelp": 'Provisioning type to '
                           'generate QR code \n(softap/ble)',
                "choices": ['softap', 'ble']
            },
            {
                "argname": "--fileid",
                "metavar": "<fileid>",
                "default": "",
                "arghelp": 'File identifier \n'
                           'Used to identify file for each node uniquely (used as filename suffix)\n'
                           'Default: <node_id> (The node id\'s generated)\n'
                           'If provided, eg. `mac_addr`(MAC address),\n'
                           'must be part of ADDITIONAL_VALUES file (provided in config)\n'
                           'and must have <count> values in the file (for each node)\n'
            },
            {
                "argname": "--local",
                "action":"store_true",
                "default": False,
                "arghelp": 'This is to determine whether to generate node ids locally\n'
            },
            {
                "argname": "--inputfile",
                "metavar": "<inputfile>",
                "default": "",
                "arghelp": 'This is the node_ids.csv file containing pre-generated node ids\n'
            },
            {
                "argname": "--prefix_num",
                "metavar": ("<start>", "<length>"),
                "nargs": 2,
                "default": [1, 6],  # Default start=1 and length=6
                "arghelp": 'Prefix number (counter) start and length (in digits) to be added for each output filename'
            },
            {
                "argname": "--prov_prefix",
                "metavar": "<prov_prefix>",
                "default": "PROV",
                "arghelp": 'Optional prefix in provisioning name (requires changes in firmware)',
            },
            {
                "argname": "--videostream",
                "action":"store_true",
                "default": False,
                "arghelp": 'Require mqtt_cred_host to be present in the response. Will throw an error if not available.',
            },
            {
                "argname": "--no-pop",
                "action":"store_true",
                "default": False,
                "arghelp": 'Generate QR code without pop field',
            }
        ]
    },
    "devicecert_register": {
        "cmd": "register",
        "help": "Register device certificate(s)\n",
        "func": "register_device_cert",
        "args": [
            {
                "argname": "--inputfile",
                "metavar": "<csvfilename>",
                "default": "",
                "arghelp": "Name of file containing node ids and certs\n"
            },
                        {
                "argname": "--groupname",
                "metavar": "<nodegroupname>",
                "default": "",
                "arghelp": "Name of the group to which node are to be added after successful registration\n"
            },
                        {
                "argname": "--type",
                "metavar": "<nodetype>",
                "default": "",
                "arghelp": "Node type\n"
            },
                        {
                "argname": "--model",
                "metavar": "<nodemodel>",
                "default": "",
                "arghelp": "Node model\n"
            },
                                    {
                "argname": "--subtype",
                "metavar": "<nodesubtype>",
                "default": "",
                "arghelp": "Node subtype\n"
            },
                       {
                "argname": "--parent_groupname",
                "metavar": "<parent_groupname>",
                "default": "",
                "arghelp": "Name of the parent group to which this newly created group will be a child group\n"
            },
                                   {
                "argname": "--tags",
                "metavar": "<node_tags>",
                "default": "",
                "arghelp": "Comma separated strings of tags to be attached to the nodes\n"
            },
            {
                "argname": "--force",
                "default": False,
                "action":"store_true",
                "arghelp": "Whether to ignore(If --force is specified) or return the error (If --force is not specified) for duplicate node registration\n"
            },
            {
                "argname": "--update_nodes",
                "default": False,
                "action":"store_true",
                "arghelp": "Whether to skip registration of the device certificates and only add the type, model, subtype and tags to the nodes(If --update_nodes is specified)\n"
            },
            {
                "argname": "--node_policies",
                "default": "",
                "metavar": "<nodepolicies>",
                "arghelp": "IoT access policies that need to be attached to the manufactured nodes, eg. mqtt,videostream\n"
            },
        ]
    },
    "devicecert_status": {
        "cmd": "getcertstatus",
        "help": "Check Device Certificate Registration Status",
        "func": "get_register_device_cert_status",
        "args": [
            {
                "argname": "--requestid",
                "metavar": "<requestid>",
                "default": "",
                "arghelp": "Request Id of device certificate registration"
            }
        ]
    }
}
