"""
Theme management for the Cybersec CLI.
"""

from pathlib import Path
from typing import Dict, Optional

from rich.theme import Theme


def load_theme(theme_name: str = "matrix") -> Theme:
    """Load the specified theme.

    Args:
        theme_name: Name of the theme to load

    Returns:
        A Rich Theme object
    """
    themes = {
        "matrix": {
            "primary": "bright_green",
            "secondary": "green",
            "success": "bright_green",
            "warning": "bright_yellow",
            "error": "bright_red",
            "info": "bright_cyan",
            "highlight": "bright_white",
            "muted": "bright_black",
            "banner": "bright_green",
            "title": "bright_cyan",
            "text": "white",
        },
        "cyberpunk": {
            "primary": "bright_magenta",
            "secondary": "bright_blue",
            "success": "bright_green",
            "warning": "bright_yellow",
            "error": "bright_red",
            "info": "bright_cyan",
            "highlight": "bright_white",
            "muted": "bright_black",
            "banner": "bright_magenta",
            "title": "bright_blue",
            "text": "white",
        },
        "minimal": {
            "primary": "white",
            "secondary": "bright_black",
            "success": "green",
            "warning": "yellow",
            "error": "red",
            "info": "blue",
            "highlight": "bright_white",
            "muted": "bright_black",
            "banner": "white",
            "title": "bright_white",
            "text": "white",
        },
    }

    # Default to matrix theme if requested theme doesn't exist
    theme_data = themes.get(theme_name.lower(), themes["matrix"])

    # Create theme with all styles
    theme_styles = {}
    for style_name, style_value in theme_data.items():
        # Add base styles
        theme_styles[style_name] = style_value

        # Add bold variants
        theme_styles[f"bold_{style_name}"] = f"bold {style_value}"

        # Add dim variants
        theme_styles[f"dim_{style_name}"] = f"dim {style_value}"

        # Add reverse variants
        theme_styles[f"reverse_{style_name}"] = f"reverse {style_value}"

    return Theme(theme_styles)


def get_available_themes() -> list:
    """Get a list of available theme names."""
    return ["matrix", "cyberpunk", "minimal"]


def save_theme_preference(theme_name: str, config_path: Optional[Path] = None) -> bool:
    """Save the user's theme preference to a config file.

    Args:
        theme_name: Name of the theme to save as preference
        config_path: Optional path to config file

    Returns:
        bool: True if successful, False otherwise
    """
    if config_path is None:
        config_path = Path.home() / ".cybersec" / "config.ini"

    try:
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, "w") as f:
            f.write(f"[ui]\ntheme = {theme_name}\n")
        return True
    except Exception as e:
        return False


def load_theme_preference(config_path: Optional[Path] = None) -> str:
    """Load the user's theme preference from config file.

    Args:
        config_path: Optional path to config file

    Returns:
        str: Name of the preferred theme, or 'matrix' if not set
    """
    if config_path is None:
        config_path = Path.home() / ".cybersec" / "config.ini"

    if not config_path.exists():
        return "matrix"

    try:
        import configparser

        config = configparser.ConfigParser()
        config.read(config_path)
        return config.get("ui", "theme", fallback="matrix")
    except Exception:
        return "matrix"
