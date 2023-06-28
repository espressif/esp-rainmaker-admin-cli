import sys
import os
from rmaker_admin_lib.logger import log
from rmaker_admin_lib.configmanager import SERVER_CONFIG_FILE

try:
    if os.path.exists(SERVER_CONFIG_FILE):
        from rmaker_admin_lib import serverconfig

        backslash = '/'
        VERSION = 'v1'
        HOST = serverconfig.BASE_URL.rstrip(backslash) + backslash + VERSION + backslash
        API_URL = serverconfig.BASE_URL.rstrip(backslash)

        TAG_REGEX = r"^ *[a-zA-Z_.0-9]+ *: *[a-zA-Z_.0-9]+[a-zA-Z_.0-9 ]* *$"
        TAG_DYNAMIC_REGEX = r"^ *[a-zA-Z_.0-9]+ *:@ *[a-zA-Z_.0-9]+[a-zA-Z_.0-9 ]* *$"
        TAG_DYNAMIC_SEPARATOR = ":@"
        COLON = ":"
        EMPTY_STRING = ""
        COMMA = ","

except Exception as e:
    log.debug(e)
    sys.exit(1)