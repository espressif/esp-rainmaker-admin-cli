# SPDX-FileCopyrightText: 2020-2025 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: Apache-2.0

import json
import os
import re
from pathlib import Path
from rmaker_admin_lib.logger import log
from rmaker_admin_lib.exceptions import InvalidConfigError

class ProfileManager:
    """
    Profile Manager class to handle multiple profiles and profile switching.
    Maintains backward compatibility with existing single-profile setup.
    No built-in profiles (unlike esp-rainmaker-cli) since admin CLI is for private accounts only.
    """
    
    # Default config directory - predictable and consistent
    # Note: Uses same base directory as esp-rainmaker-cli but different profiles subdirectory
    DEFAULT_CONFIG_DIR = os.path.expanduser('~/.espressif/rainmaker')
    
    # Profiles subdirectory for admin CLI - separate from esp-rainmaker-cli profiles
    PROFILES_SUBDIR = 'admin_profiles'
    
    # Default profile name for new configurations
    DEFAULT_PROFILE_NAME = 'default'
    
    def __init__(self, config_dir=None):
        """
        Initialize ProfileManager with optional custom config directory.
        
        :param config_dir: Optional custom config directory. If not provided,
                          uses DEFAULT_CONFIG_DIR with optional environment variable override.
        """
        self.config_dir = self._determine_config_dir(config_dir)
        self._ensure_config_dir()
        self._migrate_to_profiles_subdir()  # Migrate existing files to profiles/ subdirectory
        self._migrate_legacy_config()
    
    def _determine_config_dir(self, custom_dir=None):
        """
        Determine the configuration directory to use.
        Priority: custom_dir > environment variable > default
        """
        if custom_dir:
            return custom_dir
        
        # Check environment variable for backward compatibility
        env_dir = os.environ.get('RM_USER_CONFIG_DIR')
        if env_dir:
            return env_dir
        
        # Use default directory
        return self.DEFAULT_CONFIG_DIR
    
    def _get_profiles_dir(self):
        """Get the profiles subdirectory path."""
        return os.path.join(self.config_dir, self.PROFILES_SUBDIR)
    
    def _get_profiles_config_file(self):
        """Get the path to the profiles configuration file."""
        return os.path.join(self._get_profiles_dir(), 'profiles.json')
    
    def _get_current_profile_file(self):
        """Get the path to the current profile file."""
        return os.path.join(self._get_profiles_dir(), 'current_profile')
    
    def _get_legacy_config_file(self):
        """Get the path to the legacy configuration file."""
        return os.path.join(self.config_dir, 'rainmaker_admin_config.json')
    
    def _get_legacy_server_config_file(self):
        """Get the path to the legacy server configuration file."""
        from rmaker_admin_lib.configmanager import SERVER_CONFIG_FILE
        return SERVER_CONFIG_FILE
    
    def _ensure_config_dir(self):
        """Ensure the configuration directory and profiles subdirectory exist."""
        try:
            os.makedirs(self.config_dir, exist_ok=True)
            os.makedirs(self._get_profiles_dir(), exist_ok=True)
        except Exception as e:
            log.error(f"Failed to create config directories: {e}")
            raise
    
    def _migrate_legacy_config(self):
        """
        Migrate legacy single-profile configuration to new profile system.
        This ensures backward compatibility for existing users.
        """
        legacy_config_file = self._get_legacy_config_file()
        legacy_server_config_file = self._get_legacy_server_config_file()
        profiles_config_file = self._get_profiles_config_file()
        
        # Check if legacy config exists and profiles config doesn't
        has_legacy_config = os.path.exists(legacy_config_file)
        has_legacy_server_config = os.path.exists(legacy_server_config_file)
        
        if (has_legacy_config or has_legacy_server_config) and not os.path.exists(profiles_config_file):
            log.info("Migrating legacy configuration to profile-based system")
            
            try:
                # Create profiles config
                profiles_config = {
                    'profiles': {},
                    'custom_profiles': {}
                }
                
                # Migrate server config if it exists
                base_url = None
                if has_legacy_server_config:
                    try:
                        # Read serverconfig.py file
                        with open(legacy_server_config_file, 'r') as f:
                            content = f.read()
                            # Extract BASE_URL from serverconfig.py
                            import re
                            match = re.search(r"BASE_URL\s*=\s*['\"]([^'\"]+)['\"]", content)
                            if match:
                                base_url = match.group(1)
                                log.debug(f"Found legacy BASE_URL: {base_url}")
                    except Exception as e:
                        log.debug(f"Failed to read legacy server config: {e}")
                
                # Migrate login config if it exists
                login_data = None
                if has_legacy_config:
                    try:
                        with open(legacy_config_file, 'r') as f:
                            login_data = json.load(f)
                            log.debug(f"Found legacy login config")
                    except Exception as e:
                        log.debug(f"Failed to read legacy login config: {e}")
                
                # Create default profile if we have any legacy config
                if base_url or login_data:
                    profile_name = self.DEFAULT_PROFILE_NAME
                    
                    # Create default profile
                    custom_profile = {
                        'name': profile_name,
                        'description': 'Default profile (migrated from legacy config)',
                        'base_url': base_url or '',
                        'builtin': False
                    }
                    
                    profiles_config['custom_profiles'][profile_name] = custom_profile
                    
                    # Save profiles config
                    with open(profiles_config_file, 'w') as f:
                        json.dump(profiles_config, f, indent=2)
                    
                    # Set current profile
                    current_profile_file = self._get_current_profile_file()
                    with open(current_profile_file, 'w') as f:
                        f.write(profile_name)
                    
                    # Copy login data to profile-specific location if it exists
                    if login_data:
                        profile_config_file = self._get_profile_config_file(profile_name)
                        profile_data = {
                            'idtoken': login_data.get('idtoken'),
                            'refreshtoken': login_data.get('refreshtoken'),
                            'accesstoken': login_data.get('accesstoken')
                        }
                        
                        with open(profile_config_file, 'w') as f:
                            json.dump(profile_data, f)
                    
                    log.info(f"Legacy configuration migrated to profile '{profile_name}'")
                
            except Exception as e:
                log.error(f"Failed to migrate legacy configuration: {e}")
                # Don't raise - let it fall back to creating new config
    
    def _get_profile_config_file(self, profile_name):
        """Get the configuration file path for a specific profile."""
        return os.path.join(self._get_profiles_dir(), f'{profile_name}_config.json')
    
    def _validate_profile_name(self, profile_name):
        """
        Validate profile name according to requirements:
        alphanumeric with underscore, hyphen, dot and hash allowed as special characters, no spaces
        """
        if not profile_name:
            raise ValueError("Profile name cannot be empty")
        
        if not re.match(r'^[a-zA-Z0-9_\-\.#]+$', profile_name):
            raise ValueError("Profile name can only contain alphanumeric characters, underscore, hyphen, dot, and hash")
        
        if len(profile_name) > 50:  # Reasonable limit
            raise ValueError("Profile name too long (max 50 characters)")
    
    def _load_profiles_config(self):
        """Load profiles configuration, creating default if it doesn't exist."""
        profiles_config_file = self._get_profiles_config_file()
        
        if not os.path.exists(profiles_config_file):
            # Create default profiles config (empty, no built-in profiles)
            default_config = {
                'profiles': {},
                'custom_profiles': {}
            }
            
            with open(profiles_config_file, 'w') as f:
                json.dump(default_config, f, indent=2)
            
            return default_config
        
        try:
            with open(profiles_config_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            log.error(f"Failed to load profiles config: {e}")
            raise InvalidConfigError(f"Invalid profiles configuration: {e}")
    
    def _save_profiles_config(self, config):
        """Save profiles configuration."""
        profiles_config_file = self._get_profiles_config_file()
        try:
            with open(profiles_config_file, 'w') as f:
                json.dump(config, f, indent=2)
        except Exception as e:
            log.error(f"Failed to save profiles config: {e}")
            raise
    
    def get_current_profile(self):
        """Get the currently active profile name."""
        current_profile_file = self._get_current_profile_file()
        
        if os.path.exists(current_profile_file):
            try:
                with open(current_profile_file, 'r') as f:
                    profile_name = f.read().strip()
                    # Validate that the profile still exists
                    if self.profile_exists(profile_name):
                        return profile_name
                    else:
                        # Profile doesn't exist - clear the file and reset to default
                        # Only warn if we're actually resetting (not if default doesn't exist)
                        try:
                            os.remove(current_profile_file)
                        except Exception:
                            pass
                        if self.profile_exists(self.DEFAULT_PROFILE_NAME):
                            log.warn(f"Current profile '{profile_name}' no longer exists, resetting to default")
                            # Set default as current to avoid repeated warnings
                            self.set_current_profile(self.DEFAULT_PROFILE_NAME)
                            return self.DEFAULT_PROFILE_NAME
            except Exception as e:
                log.warn(f"Failed to read current profile: {e}")
        
        # Check if default profile exists, if not return None (no profile set)
        if self.profile_exists(self.DEFAULT_PROFILE_NAME):
            return self.DEFAULT_PROFILE_NAME
        
        return None
    
    def set_current_profile(self, profile_name):
        """Set the currently active profile."""
        if not self.profile_exists(profile_name):
            raise ValueError(f"Profile '{profile_name}' does not exist")
        
        current_profile_file = self._get_current_profile_file()
        try:
            with open(current_profile_file, 'w') as f:
                f.write(profile_name)
            log.info(f"Current profile set to '{profile_name}'")
        except Exception as e:
            log.error(f"Failed to set current profile: {e}")
            raise
    
    def profile_exists(self, profile_name):
        """Check if a profile exists."""
        profiles_config = self._load_profiles_config()
        return (profile_name in profiles_config['profiles'] or 
                profile_name in profiles_config['custom_profiles'])
    
    def get_profile_config(self, profile_name):
        """Get configuration for a specific profile."""
        profiles_config = self._load_profiles_config()
        
        if profile_name in profiles_config['profiles']:
            return profiles_config['profiles'][profile_name]
        elif profile_name in profiles_config['custom_profiles']:
            return profiles_config['custom_profiles'][profile_name]
        else:
            raise ValueError(f"Profile '{profile_name}' not found")
    
    def list_profiles(self):
        """List all available profiles."""
        profiles_config = self._load_profiles_config()
        
        all_profiles = {}
        all_profiles.update(profiles_config['profiles'])
        all_profiles.update(profiles_config['custom_profiles'])
        
        return all_profiles
    
    def create_custom_profile(self, profile_name, base_url, description=None, allow_overwrite=False):
        """Create a new custom profile.
        
        :param profile_name: Name of the profile to create
        :param base_url: Base URL for the profile
        :param description: Optional description for the profile
        :param allow_overwrite: If True, allow overwriting an existing profile (default: False)
        """
        self._validate_profile_name(profile_name)
        
        if self.profile_exists(profile_name) and not allow_overwrite:
            raise ValueError(f"Profile '{profile_name}' already exists")
        
        # Ensure base_url ends with /
        if not base_url.endswith('/'):
            base_url += '/'
        
        custom_profile = {
            'name': profile_name,
            'description': description or f'Custom profile: {profile_name}',
            'base_url': base_url,
            'builtin': False
        }
        
        profiles_config = self._load_profiles_config()
        profiles_config['custom_profiles'][profile_name] = custom_profile
        self._save_profiles_config(profiles_config)
        
        log.info(f"Created custom profile '{profile_name}' with base URL '{base_url}'")
    
    def delete_custom_profile(self, profile_name):
        """Delete a custom profile."""
        # Prevent deletion of the default profile
        if profile_name == self.DEFAULT_PROFILE_NAME:
            raise ValueError(f"Cannot delete the '{self.DEFAULT_PROFILE_NAME}' profile. It is a required system profile.")
        
        profiles_config = self._load_profiles_config()
        
        if profile_name not in profiles_config['custom_profiles']:
            raise ValueError(f"Custom profile '{profile_name}' not found")
        
        # Check if this is the current profile BEFORE deleting it
        # Read current_profile file directly to avoid validation issues
        current_profile_file = self._get_current_profile_file()
        is_current_profile = False
        if os.path.exists(current_profile_file):
            try:
                with open(current_profile_file, 'r') as f:
                    current_profile = f.read().strip()
                    if current_profile == profile_name:
                        is_current_profile = True
            except Exception:
                pass
        
        # Remove profile configuration
        del profiles_config['custom_profiles'][profile_name]
        self._save_profiles_config(profiles_config)
        
        # Remove profile's token file
        profile_config_file = self._get_profile_config_file(profile_name)
        if os.path.exists(profile_config_file):
            os.remove(profile_config_file)
        
        # If this was the current profile, clear current profile and reset to default
        if is_current_profile:
            # Clear the current_profile file first
            if os.path.exists(current_profile_file):
                os.remove(current_profile_file)
            # Automatically switch to default if it exists
            if self.profile_exists(self.DEFAULT_PROFILE_NAME):
                # Set default without validation to avoid recursive calls
                try:
                    with open(current_profile_file, 'w') as f:
                        f.write(self.DEFAULT_PROFILE_NAME)
                    log.info(f"Current profile '{profile_name}' no longer exists, resetting to default")
                except Exception as e:
                    log.error(f"Failed to set default profile: {e}")
        
        log.info(f"Deleted custom profile '{profile_name}'")
    
    def get_profile_tokens(self, profile_name):
        """Get tokens for a specific profile."""
        profile_config_file = self._get_profile_config_file(profile_name)
        
        if not os.path.exists(profile_config_file):
            return None, None, None
        
        try:
            with open(profile_config_file, 'r') as f:
                data = json.load(f)
                return data.get('idtoken'), data.get('refreshtoken'), data.get('accesstoken')
        except Exception as e:
            log.error(f"Failed to load tokens for profile '{profile_name}': {e}")
            raise
    
    def set_profile_tokens(self, profile_name, idtoken=None, refreshtoken=None, accesstoken=None):
        """Set tokens for a specific profile."""
        profile_config_file = self._get_profile_config_file(profile_name)
        
        # Load existing data or create new
        token_data = {}
        if os.path.exists(profile_config_file):
            try:
                with open(profile_config_file, 'r') as f:
                    token_data = json.load(f)
            except Exception as e:
                log.warn(f"Failed to load existing tokens, creating new: {e}")
        
        # Update tokens
        if idtoken is not None:
            token_data['idtoken'] = idtoken
        if refreshtoken is not None:
            token_data['refreshtoken'] = refreshtoken
        if accesstoken is not None:
            token_data['accesstoken'] = accesstoken
        
        # Save updated tokens
        try:
            with open(profile_config_file, 'w') as f:
                json.dump(token_data, f)
            log.debug(f"Updated tokens for profile '{profile_name}'")
        except Exception as e:
            log.error(f"Failed to save tokens for profile '{profile_name}': {e}")
            raise
    
    def clear_profile_tokens(self, profile_name):
        """Clear tokens for a specific profile."""
        profile_config_file = self._get_profile_config_file(profile_name)
        
        if os.path.exists(profile_config_file):
            os.remove(profile_config_file)
            log.info(f"Cleared tokens for profile '{profile_name}'")
    
    def has_profile_tokens(self, profile_name):
        """Check if a profile has stored tokens."""
        idtoken, refreshtoken, accesstoken = self.get_profile_tokens(profile_name)
        return accesstoken is not None
    
    def _migrate_to_profiles_subdir(self):
        """
        Migrate existing profile files to profiles/ subdirectory for better organization.
        This handles the case where profile files already exist in the main config directory.
        """
        profiles_dir = self._get_profiles_dir()
        
        # Files to migrate to profiles/ subdirectory
        files_to_migrate = [
            'profiles.json',
            'current_profile'
        ]
        
        # Check if any profile files exist in the main config directory
        files_found = []
        for filename in files_to_migrate:
            old_path = os.path.join(self.config_dir, filename)
            if os.path.exists(old_path):
                files_found.append((filename, old_path))
        
        # Also check for custom profile config files (pattern: *_config.json but not rainmaker_admin_config.json)
        import glob
        config_pattern = os.path.join(self.config_dir, '*_config.json')
        for filepath in glob.glob(config_pattern):
            filename = os.path.basename(filepath)
            if filename != 'rainmaker_admin_config.json':
                files_found.append((filename, filepath))
        
        if files_found:
            log.info(f"Migrating {len(files_found)} profile files to profiles/ subdirectory")
            
            try:
                # Ensure profiles directory exists
                os.makedirs(profiles_dir, exist_ok=True)
                
                # Move each file
                for filename, old_path in files_found:
                    new_path = os.path.join(profiles_dir, filename)
                    
                    # Skip if source file doesn't exist (already moved)
                    if not os.path.exists(old_path):
                        continue
                    
                    # If destination already exists, back it up
                    if os.path.exists(new_path):
                        backup_path = f"{new_path}.backup"
                        if os.path.exists(backup_path):
                            os.remove(backup_path)
                        os.rename(new_path, backup_path)
                        log.info(f"Backed up existing {filename} to {filename}.backup")
                    
                    # Move the file
                    try:
                        os.rename(old_path, new_path)
                        log.info(f"Moved {filename} to profiles/ subdirectory")
                    except OSError as e:
                        log.warn(f"Failed to move {filename}: {e}")
                        continue
                
                log.info("Profile files migration completed successfully")
                
            except Exception as e:
                log.error(f"Failed to migrate profile files to subdirectory: {e}")
                # Don't raise - this is a non-critical migration
