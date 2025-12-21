"""
Configuration management for Cybersec CLI.
"""
import os
from pathlib import Path
from typing import Dict, Any, Optional
import yaml
from pydantic import BaseModel, Field, validator
from dotenv import load_dotenv

# Load environment variables from .env file if it exists
load_dotenv()

class AIConfig(BaseModel):
    """AI-related configuration."""
    provider: str = "openai"  # openai, anthropic, ollama
    model: str = "gpt-4"
    api_key: Optional[str] = None
    temperature: float = 0.7
    max_tokens: int = 2000
    
    class Config:
        env_prefix = "AI_"
        extra = "ignore"

class ScanningConfig(BaseModel):
    """Scanning-related configuration."""
    default_timeout: int = 2
    max_threads: int = 50
    rate_limit: int = 10  # requests per second
    adaptive_scanning: bool = True  # Enable adaptive concurrency control
    enhanced_service_detection: bool = True  # Enable enhanced service detection
    
    class Config:
        env_prefix = "SCAN_"
        extra = "ignore"

class UIConfig(BaseModel):
    """UI-related configuration."""
    theme: str = "matrix"
    show_banner: bool = True
    color_output: bool = True
    animation_speed: str = "normal"  # slow, normal, fast, off
    
    class Config:
        env_prefix = "UI_"
        extra = "ignore"

class SecurityConfig(BaseModel):
    """Security-related configuration."""
    require_confirmation: bool = True
    log_all_commands: bool = True
    encrypt_stored_data: bool = True
    
    class Config:
        env_prefix = "SECURITY_"
        extra = "ignore"

class RedisConfig(BaseModel):
    """Redis-related configuration."""
    url: str = "redis://localhost:6379"
    password: Optional[str] = None
    db: int = 0
    enabled: bool = True
    
    class Config:
        env_prefix = "REDIS_"
        extra = "ignore"

class OutputConfig(BaseModel):
    """Output-related configuration."""
    default_format: str = "table"  # table, json, csv, markdown
    save_results: bool = True
    export_path: str = "./reports/"
    
    class Config:
        env_prefix = "OUTPUT_"
        extra = "ignore"

class Config(BaseModel):
    """Main configuration model."""
    ai: AIConfig = Field(default_factory=AIConfig)
    scanning: ScanningConfig = Field(default_factory=ScanningConfig)
    ui: UIConfig = Field(default_factory=UIConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    redis: RedisConfig = Field(default_factory=RedisConfig)
    
    @classmethod
    def from_dict(cls, config_dict: Dict[str, Any]) -> 'Config':
        """Create a Config instance from a dictionary."""
        return cls(**config_dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the config to a dictionary."""
        return self.dict()
    
    def save(self, path: Optional[Path] = None) -> bool:
        """Save the configuration to a file."""
        if path is None:
            path = self._get_default_config_path()
            
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, 'w') as f:
                yaml.safe_dump(self.dict(), f, default_flow_style=False)
            return True
        except Exception as e:
            return False
    
    @classmethod
    def load(cls, path: Optional[Path] = None) -> 'Config':
        """Load configuration from a file."""
        if path is None:
            path = cls._get_default_config_path()
            
        if not path.exists():
            return cls()
            
        try:
            with open(path, 'r') as f:
                config_dict = yaml.safe_load(f) or {}
            return cls.from_dict(config_dict)
        except Exception as e:
            return cls()
    
    @classmethod
    def _get_default_config_path(cls) -> Path:
        """Get the default configuration file path."""
        config_dir = Path.home() / ".cybersec"
        return config_dir / "config.yaml"

# Global settings instance
settings = Config.load()

# Load API keys from environment variables
if not settings.ai.api_key:
    settings.ai.api_key = os.getenv("OPENAI_API_KEY")

# Ensure export directory exists
if settings.output.save_results:
    Path(settings.output.export_path).mkdir(parents=True, exist_ok=True)
