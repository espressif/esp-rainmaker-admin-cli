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
    # Try to get BASE_URL from profile first, then fall back to serverconfig.py
    base_url = None
    
    # Check if profile manager is available and has a current profile
    try:
        from rmaker_admin_lib.profile_manager import ProfileManager
        profile_manager = ProfileManager()
        current_profile = profile_manager.get_current_profile()
        if current_profile:
            try:
                profile_config = profile_manager.get_profile_config(current_profile)
                base_url = profile_config.get('base_url')
                if base_url:
                    log.debug(f"Using BASE_URL from profile '{current_profile}': {base_url}")
            except Exception:
                pass
    except Exception:
        pass
    
    # Fall back to serverconfig.py if no profile base_url found
    if not base_url and os.path.exists(SERVER_CONFIG_FILE):
        try:
            from rmaker_admin_lib import serverconfig
            base_url = serverconfig.BASE_URL
            log.debug(f"Using BASE_URL from serverconfig.py: {base_url}")
        except Exception as e:
            log.debug(f"Failed to import or read serverconfig: {type(e).__name__} - {str(e)}")
            base_url = None
    
    if base_url:
        backslash = '/'
        HOST = base_url.rstrip(backslash) + backslash + VERSION + backslash
        API_URL = base_url.rstrip(backslash)
    else:
        # If no BASE_URL found, set defaults (will cause errors if used without config)
        HOST = None
        API_URL = None

except Exception as e:
    import traceback
    log.debug("Exception while initializing constants: {} - {}".format(type(e).__name__, str(e)))
    log.debug("Traceback: {}".format(traceback.format_exc()))
    # Don't exit - let it fail gracefully when HOST/API_URL are accessed
    HOST = None
    API_URL = None