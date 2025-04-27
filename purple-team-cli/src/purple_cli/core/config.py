"""
Module for handling application configuration.

Loads configuration from standard locations and provides access
to settings.
"""

import os
import json
from pathlib import Path
from typing import Dict, Any, Optional, Union

# Define default configuration values
DEFAULT_CONFIG = {
    "atomics_path": "",
    "powershell_path": "powershell",  # Default to system's PowerShell
    "timeout": 300,  # Default timeout in seconds
}

class AppConfig:
    """Represents the application configuration."""

    def __init__(self, config_path: Optional[str] = None):
        """
        Initializes the configuration object.

        Args:
            config_path: Optional path to a specific config file.
                       If None, uses default locations.
        """
        self.config: Dict[str, Any] = {}
        self.config_path = self._determine_config_path(config_path)
        self._load_config()

    def _determine_config_path(self, config_path: Optional[str] = None) -> Path:
        """
        Determines the path to the configuration file.
        
        Args:
            config_path: Optional path to the configuration file.
            
        Returns:
            Path to the configuration file.
        """
        if config_path:
            return Path(config_path)
        
        # Use standard OS-specific config directories
        if os.name == "nt":  # Windows
            base_dir = Path(os.environ.get("APPDATA", "")) / "PurpleTeamCLI"
        else:  # Unix/Linux/MacOS
            base_dir = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "purpleteam"
        
        # Create directory if it doesn't exist
        os.makedirs(base_dir, exist_ok=True)
        
        return base_dir / "config.json"

    def _load_config(self) -> None:
        """
        Loads configuration from file or initializes with defaults.
        """
        self.config = DEFAULT_CONFIG.copy()
        
        try:
            if self.config_path.exists():
                with open(self.config_path, "r") as f:
                    loaded_config = json.load(f)
                    # Update the default configuration with loaded values
                    self.config.update(loaded_config)
        except (json.JSONDecodeError, IOError) as e:
            # If there's an error reading the config, use defaults
            print(f"Warning: Error reading config file: {e}. Using default configuration.")

    def save_config(self) -> bool:
        """
        Saves the current configuration to the config file.
        
        Returns:
            True if the configuration was saved successfully, False otherwise.
        """
        try:
            with open(self.config_path, "w") as f:
                json.dump(self.config, f, indent=2)
            return True
        except IOError as e:
            print(f"Error saving config file: {e}")
            return False

    def get_setting(self, key: str) -> Any:
        """
        Retrieves a configuration setting.

        Args:
            key: The configuration key to retrieve.

        Returns:
            The value of the setting, or None if not found.
        """
        return self.config.get(key)

    def update_setting(self, key: str, value: Any) -> None:
        """
        Updates a configuration setting.

        Args:
            key: The configuration key to update.
            value: The new value for the setting.
        """
        self.config[key] = value

    @property
    def atomics_path(self) -> str:
        """
        Gets the path to the Atomic Red Team atomics directory.
        
        Returns:
            Path to the atomics directory.
        """
        return self.get_setting("atomics_path")

    @atomics_path.setter
    def atomics_path(self, path: str) -> None:
        """
        Sets the path to the Atomic Red Team atomics directory.
        
        Args:
            path: Path to the atomics directory.
        """
        self.update_setting("atomics_path", path)

    @property
    def powershell_path(self) -> str:
        """
        Gets the path to the PowerShell executable.
        
        Returns:
            Path to the PowerShell executable.
        """
        return self.get_setting("powershell_path")

    @powershell_path.setter
    def powershell_path(self, path: str) -> None:
        """
        Sets the path to the PowerShell executable.
        
        Args:
            path: Path to the PowerShell executable.
        """
        self.update_setting("powershell_path", path)

    @property
    def timeout(self) -> int:
        """
        Gets the timeout for command execution in seconds.
        
        Returns:
            Timeout for command execution in seconds.
        """
        return self.get_setting("timeout")

    @timeout.setter
    def timeout(self, seconds: int) -> None:
        """
        Sets the timeout for command execution.
        
        Args:
            seconds: Timeout for command execution in seconds.
        """
        self.update_setting("timeout", seconds)


# Create a singleton instance of AppConfig
_config_instance: Optional[AppConfig] = None

def get_config(config_path: Optional[str] = None) -> AppConfig:
    """
    Get the application configuration singleton.
    
    Args:
        config_path: Optional path to the configuration file.
        
    Returns:
        The application configuration instance.
    """
    global _config_instance
    if _config_instance is None:
        _config_instance = AppConfig(config_path)
    return _config_instance