"""
Configuration for plsaicheckyay
"""

import os
import json
from pathlib import Path
from typing import Dict, Any, Optional


class Config:
    """Manages application configuration"""
    
    def __init__(self):
        """Initialize configuration manager and load existing config"""
        self.config_dir = Path.home() / ".config" / "plsaicheckyay"
        self.config_file = self.config_dir / "config.json"
        self._config = self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file"""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Error loading configuration: {e}")
        
        return self._default_config()
    
    def _default_config(self) -> Dict[str, Any]:
        """Default configuration"""
        return {
            "ai_provider": "ollama",
            "ollama": {
                "host": "http://localhost:11434",
                "model": "llama3.1"
            },
            "openai": {
                "model": "gpt-4"
            },
            "openrouter": {
                "model": "anthropic/claude-3.5-sonnet"
            },
            "security": {
                "min_confidence_threshold": 0.7,
                "auto_install_safe_packages": False,
                "always_ask_confirmation": True
            }
        }
    
    def save(self):
        """Save configuration to file"""
        self.config_dir.mkdir(parents=True, exist_ok=True)
        with open(self.config_file, 'w') as f:
            json.dump(self._config, f, indent=2)
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value"""
        keys = key.split('.')
        value = self._config
        for k in keys:
            value = value.get(k, {})
            if not isinstance(value, dict):
                return value
        return default if value == {} else value
    
    def set(self, key: str, value: Any):
        """Set a configuration value"""
        keys = key.split('.')
        config = self._config
        for k in keys[:-1]:
            config = config.setdefault(k, {})
        config[keys[-1]] = value
    
    def get_api_key(self, provider: str) -> Optional[str]:
        """Get API key for a provider"""
        # First check environment variables
        env_vars = {
            "openai": "OPENAI_API_KEY",
            "openrouter": "OPENROUTER_API_KEY"
        }
        
        if provider in env_vars:
            key = os.getenv(env_vars[provider])
            if key:
                return key
        
        # Then check configuration
        return self.get(f"{provider}.api_key")


# Global configuration instance
config = Config()


def setup_config():
    """Interactive configuration setup"""
    print("🛠️  plsaicheckyay Configuration")
    print("Press Enter to keep current value\n")
    
    # AI Provider
    current_provider = config.get("ai_provider")
    provider = input(f"AI Provider (ollama/openai/openrouter) [{current_provider}]: ").strip()
    if provider:
        config.set("ai_provider", provider)
    else:
        provider = current_provider
    
    # Provider-specific configuration
    if provider == "ollama":
        host = input(f"OLLAMA Host [{config.get('ollama.host')}]: ").strip()
        if host:
            config.set("ollama.host", host)
        
        model = input(f"OLLAMA Model [{config.get('ollama.model')}]: ").strip()
        if model:
            config.set("ollama.model", model)
    
    elif provider in ["openai", "openrouter"]:
        api_key = input(f"API Key for {provider}: ").strip()
        if api_key:
            config.set(f"{provider}.api_key", api_key)
        
        model = input(f"Model for {provider} [{config.get(f'{provider}.model')}]: ").strip()
        if model:
            config.set(f"{provider}.model", model)
    
    # Security configurations
    print("\n🔒 Security configurations")
    
    threshold = input(f"Minimum confidence threshold (0.0-1.0) [{config.get('security.min_confidence_threshold')}]: ").strip()
    if threshold:
        try:
            config.set("security.min_confidence_threshold", float(threshold))
        except ValueError:
            print("⚠️  Invalid threshold value")
    
    auto_install = input("Automatically install safe packages? (y/n) [n]: ").strip().lower()
    if auto_install in ['y', 'yes']:
        config.set("security.auto_install_safe_packages", True)
    elif auto_install in ['n', 'no']:
        config.set("security.auto_install_safe_packages", False)
    
    # Save configuration
    config.save()
    print(f"\n✅ Configuration saved to {config.config_file}")


if __name__ == "__main__":
    setup_config()