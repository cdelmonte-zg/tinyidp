"""Basic tests for TinyIDP."""

import pytest


def test_import():
    """Test that the package can be imported."""
    import tinyidp
    assert tinyidp is not None


def test_config_import():
    """Test that config module can be imported."""
    from tinyidp.config import ConfigManager
    assert ConfigManager is not None


def test_app_import():
    """Test that app module can be imported."""
    from tinyidp.app import create_app
    assert create_app is not None
