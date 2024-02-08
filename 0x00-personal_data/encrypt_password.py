#!/usr/bin/env python3
"""
Defining a hash_password function
returning a hashed password
"""
import bcrypt
from bcrypt import hashpw


def hash_password(password: str) -> bytes:
    """
    Returning a hashed password
    Args:
        password (str): Is the password to be hashed
    """
    b = password.encode()
    hashed = hashpw(b, bcrypt.gensalt())
    return hashed


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Checking whether a password is valid
    Args:
        hashed_password (bytes): Is the hashed password
        password (str): Is thw password in string
    Return:
        bool
    """
    return bcrypt.checkpw(password.encode(), hashed_password)
