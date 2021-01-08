"""
Cryptographer - A Python Cryptography and Hashing Module

Ciphers Included: 
    - Vigenere Cipher (VigenereKey)
    - RSA Cipher (RSAKey)
Hashers Included:
    - Salted Password Hasher (Password)

All of the above ciphers and hashers are combined into one class: 
    - The Cryptographer (Cryptographer)

Setup: 
    >>> from cryptographer import *
"""

import hashlib
import hmac
import os
import secrets

from .util import truncate
from .ciphers.rsa import RSAKey
from .ciphers.vigenere import VigenereKey
from .hashers.passwords import Password
from .cryptographer import Cryptographer

__all__ = [
    "VigenereKey",
    "RSAKey",
    "Password",
    "Cryptographer",
]
