import hashlib
import hmac
import os

from cryptographer.util import truncate


class Password:
    """
    Secure Password Hashing and Validation

    Usage: 
        >>> pwd = Password('secret') # also works with b'secret'
        >>> pwd.salt
        b'\x932$Y\xb6\x08\xf6\x9b\x12_\xba\xe6...'
        >>> pwd.hash
        'bc1c75b36ae13f22d1f5b17fe9a9a6774241ccb06ed2fe...'
        >>> pwd.check_password('secret')
        True
        >>> pwd.check_password('password')
        False
    
    Pickling: 
        >>> import pickle
        >>> pickle.dump(pwd, open('pwd.dat', 'wb'))
    
    Copying: 
        >>> pwd2 = pwd.copy()
        >>> pwd == pwd2
        True
    
    Custom Iterations: 
        >>> class MyPassword(Password):
                iterations = 10**7 # default is 10**6
        >>> pwd = MyPassword('secret')
        >>> pwd = pwd.copy() # convert to Password type (optional)
    """

    iterations = 10**6

    def __init__(self, pwd, salt=None, salt_length=4096) -> None:
        if isinstance(pwd, str):
            pwd = pwd.encode()
        if salt is None:
            salt = os.urandom(salt_length)
            
        self.salt = salt
        self.hash = self.generate_hash(pwd)

    def generate_hash(self, pwd) -> str:
        """generate password hash of pwd and return it"""
        if isinstance(pwd, str):
            pwd = pwd.encode()
        return hashlib.pbkdf2_hmac('sha256', pwd, self.salt, self.iterations).hex()

    def check_password(self, pwd) -> bool:
        """check if pwd is the correct password"""
        pwd_hash = self.generate_hash(pwd)
        valid = hmac.compare_digest(pwd_hash, self.hash)
        return valid
    
    def copy(self):
        """return a copy of self"""
        pwd = object.__new__(Password)
        pwd.salt = self.salt
        pwd.hash = self.hash
        return pwd

    def __repr__(self) -> str:
        """return repr(self)"""
        return f'<Password salt={truncate(self.salt)} hash={truncate(self.hash)} iterations={truncate(str(self.iterations))}>'

    __str__ = __repr__
    __str__.__doc__ = """return str(self)"""

    def __eq__(self, other) -> bool:
        """return self == other"""
        return other.salt == self.salt and \
               other.hash == self.hash

    def __bytes__(self) -> bytes:
        """return bytes(self)"""
        return self.hash

    def __getstate__(self) -> dict:
        """Prepare self for pickling."""
        return {
            'salt': self.salt,
            'hash': self.hash,
            }

    def __setstate__(self, data) -> None:
        """Prepare self for unpickling."""
        self.salt = data.get('salt')
        self.hash = data.get('hash')
