"""Tests for main module."""

from my_project.main import main

def test_main(capsys):
    """Test main function."""
    main()
    captured = capsys.readouterr()
    assert captured.out == "Hello, World!\n"

