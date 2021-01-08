from .ciphers.rsa import RSAKey
from .ciphers.vigenere import VigenereKey
from .hashers.passwords import Password
from .util import truncate


class Cryptographer:
    """
    Secure Combination of: 
        - VigenereKey
        - RSAKey
        - Password

    Usage: 
        >>> c = Cryptographer(password='secret') # also works with b'hello'
        >>> encrypted = c.encrypt('hello world') # also works with b'hello world'
        >>> encrypted
        b'\x00L\x1b2\x1e\x1cy\x00\\fE\xf0\x04\r\x00Bs\x9c\xfc\x9b...'
        >>> decrypted = c.decrypt(encrypted)
        >>> decrypted
        b'hello world'
    
    Pickling: 
        >>> import pickle
        >>> pickle.dump(c, open('c.dat', 'wb'))
    
    Copying: 
        >>> c2 = c.copy()
        >>> c == c2
        True
    
    Password Validation: 
        >>> c.validate_password('secret')
        True
        >>> c.validate_password('password')
        False
    
    Dictionary Conversion: 
        >>> d = c.todict()
        >>> c2 = Cryptographer.fromdict(d)
    
    Safely Sharing Data: 
        >>> share = c.share()
        >>> type(share)
        <class 'dict'>
    
    Receiving Shared Data: 
        >>> c2 = Cryptographer.fromshare(share)
    """
    def __init__(
        self, 
        password=None, 
        password_cls=Password, 
        password_object=None, 
        password_salt=None, 
        password_hash=None, 
        rsa=None, 
        vig=None, 
        pwd_vig=None
        ) -> None:
        if password_object is None:
            if password is not None:
                self.password = password_cls(password)
            elif password_salt is not None:
                self.password = password_cls(salt=password_salt)
            elif password_hash is not None and password_salt is not None:
                self.password = object.__new__(password_cls)
                password.hash = password_hash
                password.salt = password_salt
            else:
                self.password = password_cls('')
        else:
            self.password = password_cls(password)
        if rsa is None:
            self.rsa = RSAKey()
        else:
            self.rsa = RSAKey()
        if vig is None:
            self.vig = VigenereKey()
        else:
            self.vig = vig
        if pwd_vig is None:
            self.pwd_vig = VigenereKey(key=self.password.salt)
        else:
            self.pwd_vig = pwd_vig
    
    def __repr__(self) -> str:
        """return repr(self)"""
        return f'<Cryptographer password={truncate(self.password.hash)!r}>'
    
    __str__ = __repr__
    __str__.__doc__ = """return str(self)"""

    def __eq__(self, other) -> bool:
        """return self == other"""
        return other.__getstate__() == self.__getstate__()
    
    def copy(self):
        """return copy of self"""
        c = object.__new__(Cryptographer)
        c.__setstate__(self.__getstate__())
        return c
    
    def encrypt(self, data) -> bytes:
        """encrypt data"""
        result = self.pwd_vig.encrypt(data)
        result = self.vig.encrypt(result)
        result = self.rsa.encrypt(result)
        return result
    
    def decrypt(self, data) -> bytes:
        """decrypt data"""
        result = self.rsa.decrypt(data)
        result = self.vig.decrypt(result)
        result = self.pwd_vig.decrypt(result)
        return result
    
    def __getstate__(self) -> dict:
        """Prepare self for pickling."""
        return {
            'password': self.password,
            'rsa': self.rsa,
            'vig': self.vig,
            'pwd_vig': self.pwd_vig,
        }
    
    def __setstate__(self, data) -> None:
        """Prepare self for unpickling."""
        self.password = data.get('password')
        self.rsa = data.get('rsa')
        self.vig = data.get('vig')
        self.pwd_vig = data.get('pwd_vig')
    
    def todict(self) -> dict:
        """return dict(self)"""
        return self.__getstate__()
    
    def share(self) -> dict:
        """return safe-to-share dict of self"""
        return {
            'rsa': self.rsa.get_public(),
            'vig': self.vig.key,
            'pwd_vig': self.pwd_vig.key,
        }
    
    def fromdict(data):
        """return cryptographer from data"""
        cryptographer = object.__new__(Cryptographer)
        cryptographer.__setstate__(data)
        return cryptographer
    
    def fromshare(data):
        """return cryptographer from data"""
        cryptographer = object.__new__(Cryptographer)
        cryptographer.rsa = RSAKey(keys=(data.get('rsa')[0], None, data.get('rsa')[1]))
        cryptographer.vig = VigenereKey(key=data.get('vig'))
        cryptographer.pwd_vig = VigenereKey(key=data.get('pwd_vig'))
        return cryptographer
    
    def validate_password(self, password) -> bool:
        """validate password"""
        return self.password.check_password(password)
