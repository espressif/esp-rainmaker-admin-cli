#!/usr/bin/env python

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

import traceback
from rmaker_admin_lib.cli import ArgParser
from rmaker_admin_lib.logger import log


def main():
    try:
        # Setup CLI
        argparse_obj = ArgParser()
        parent_subparser = argparse_obj.setup(dest='parent_ops')
        if not parent_subparser:
            return

        # Setup CLI command for Account Operations
        acc_cmd_parser, acc_cmd_subparser = argparse_obj.set_command(
            parent_subparser,
            'account',
            dest='account_ops')

        # Setup CLI command for Account Server Config Operations
        argparse_obj.set_sub_command(acc_cmd_subparser, 'serverconfig')

        # Setup CLI command for Account Login Operations
        argparse_obj.set_sub_command(acc_cmd_subparser, 'login')

        # Setup CLI command for Certs Operations
        certs_cmd_parser, certs_cmd_subparser = argparse_obj.set_command(
            parent_subparser,
            'certs',
            dest='certs_ops')

        # Setup CLI command for Certs CA Operations
        cacert_cmd_parser, cacert_cmd_subparser = argparse_obj.set_command(
            certs_cmd_subparser,
            'cacert',
            dest='cacert_ops')
        argparse_obj.set_sub_command(cacert_cmd_subparser, 'cacert_generate')

        # Setup CLI for Certs Device Operations
        devicecert_cmd_parser, devicecert_cmd_subparser = argparse_obj.set_command(
            certs_cmd_subparser,
            'devicecert',
            dest='devicecert_ops')
        argparse_obj.set_sub_command(devicecert_cmd_subparser,
                                     'devicecert_generate')
        argparse_obj.set_sub_command(devicecert_cmd_subparser,
                                     'devicecert_register')
        argparse_obj.set_sub_command(devicecert_cmd_subparser,
                                     'devicecert_status')

        # Set parsers to print help for associated commands
        PARSER_HELP_PRINT = {
            'parent_ops': argparse_obj.parser,
            'account_ops': acc_cmd_parser,
            'certs_ops': certs_cmd_parser,
            'cacert_ops': cacert_cmd_parser,
            'devicecert_ops': devicecert_cmd_parser}

        args = argparse_obj.parse_args()

        if 'func' in args and args.func is not None:
            args.func(vars=vars(args))
        else:
            cmd_parser = None
            # Print parser help for associated command
            for cmd,val in vars(args).items():
                if val is None:
                    cmd_parser = cmd
                    break
            if cmd_parser:
                print(PARSER_HELP_PRINT[cmd_parser].format_help())

    except Exception as err:
        log.error(err)
        print(traceback.format_exc())


if __name__ == '__main__':
    main()
