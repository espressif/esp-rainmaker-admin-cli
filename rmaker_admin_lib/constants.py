import sys
import os
from rmaker_admin_lib.logger import log
from rmaker_admin_lib.configmanager import SERVER_CONFIG_FILE

TAG_REGEX = r"^ *[\p{L}\p{M}_.0-9]+ *: *[\p{L}\p{M}_.0-9@<>(){}$+=#'&%-]+[\p{L}\p{M}_.0-9-=+<>(){}$+@#'&% ]* *$"
TAG_DYNAMIC_REGEX = r"^ *[\p{L}\p{M}_.0-9]+ *:@ *[\p{L}\p{M}_.0-9@<>(){}$+=#'&%-]+[\p{L}\p{M}_.0-9-=+<>(){}$+@#'&% ]* *$"
TAG_DYNAMIC_SEPARATOR = ":@"
COLON = ":"
EMPTY_STRING = ""
COMMA = ","
VERSION = 'v1'
MQTT_PREFIX_SUBFOLDER_REGEX = r'([a-zA-Z0-9]+)(?:-ats|\.ats)\.iot'
BLUETOOTH = 'BLE'
CSV_EXTENSION = '.csv'
NAMESPACE_KEY = 'namespace'
REPEAT_TAG = 'REPEAT'

try:
    if os.path.exists(SERVER_CONFIG_FILE):
        from rmaker_admin_lib import serverconfig

        backslash = '/'
        HOST = serverconfig.BASE_URL.rstrip(backslash) + backslash + VERSION + backslash
        API_URL = serverconfig.BASE_URL.rstrip(backslash)


except Exception as e:
    log.debug(e)
    sys.exit(1)