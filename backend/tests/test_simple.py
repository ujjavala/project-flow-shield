import pytest


def test_simple():
    """Simple test to verify pytest is working"""
    assert 1 + 1 == 2


def test_string():
    """Test string operations"""
    assert "hello" + " " + "world" == "hello world"


class TestMath:
    """Test class for basic math operations"""
    
    def test_addition(self):
        assert 5 + 3 == 8
    
    def test_subtraction(self):
        assert 10 - 4 == 6
    
    def test_multiplication(self):
        assert 3 * 4 == 12
    
    def test_division(self):
        assert 15 / 3 == 5