"""Tests for utils module."""

from my_project.utils import add_numbers

def test_add_numbers():
    """Test add_numbers function."""
    assert add_numbers(1, 2) == 3
    assert add_numbers(-1, 1) == 0
    assert add_numbers(0, 0) == 0
