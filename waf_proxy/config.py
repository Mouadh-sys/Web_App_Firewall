"""Configuration loader and validator."""
import os
import yaml
import logging
from waf_proxy.models import Config

logger = logging.getLogger(__name__)


def load_config(config_path: str = None) -> Config:
    """
    Load and validate configuration from YAML file.

    Args:
        config_path: Path to YAML config file. If None, uses CONFIG_PATH env var.

    Returns:
        Validated Config object.

    Raises:
        FileNotFoundError: If config file not found.
        ValueError: If config is invalid.
    """
    if config_path is None:
        config_path = os.environ.get('CONFIG_PATH', 'configs/example.yaml')

    logger.info(f"Loading configuration from {config_path}")

    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Config file not found: {config_path}")

    with open(config_path, 'r') as f:
        data = yaml.safe_load(f)

    if not data:
        raise ValueError("Config file is empty")

    # Validate and parse config
    try:
        config = Config(**data)
        logger.info("Configuration loaded and validated successfully")
        return config
    except ValueError as e:
        logger.error(f"Configuration validation failed: {e}")
        raise

