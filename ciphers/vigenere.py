import os

from cryptographer.util import truncate


class VigenereKey:
    """
    Secure Vigenere Cryptography

    Usage: 
        >>> vig = VigenereKey() # You could say, VigenereKey(key_length=KEY_LENGTH)
        >>> vig.key.decode() # A key of length that defaults to 4096
        '58c6347e9012ea1f0c39...'
        >>> encrypted = vig.encrypt('hello world') # also works with b'hello world'
        >>> encrypted
        '9d9dcfa2a254aed4ab9c95'
        >>> decrypted = vig.decrypt(encrypted)
        >>> decrypted
        b'hello world'

    Pickling:
        >>> import pickle
        >>> pickle.dump(vig, open('vigenere.dat', 'wb'))
    
    Copying:
        >>> vig2 = vig.copy()
    """

    def __init__(self, key_length=4096, key=None) -> None:
        if key is None:
            key = self.generate_key(key_length)

        key = key.hex().encode() if isinstance(key, bytes) else key.encode()
        self.key = key
    
    def __getstate__(self) -> dict:
        """Prepare self for pickling."""
        return {
            'salt': self.salt,
            'key': self.key,
        }
    
    def __setstate__(self, data) -> None:
        """Prepare self for unpickling."""
        self.salt = data.get('salt')
        self.key = data.get('key')
    
    def __repr__(self) -> str:
        """return repr(self)"""
        return f'<VigenereKey key={truncate(self.key.decode())!r}>'
    
    __str__ = __repr__
    __str__.__doc__ = """return str(self)"""

    def __bytes__(self) -> bytes:
        """return bytes(self)"""
        return self.key

    def copy(self):
        """return a copy of self"""
        return VigenereKey(key=self.key)

    def encrypt(self, data) -> str:
        """encrypt data with self.key"""
        assert len(data) <= len(self.key), "Key must be at least as long as data"

        data = data if isinstance(data, bytes) else data.encode()
        chars = []

        for i in range(len(data)):
            char = data[i]
            key_char = self.key[i]
            final_char = (char + key_char) % 256
            chars.append(final_char)
        
        result = bytes(chars)
        return result.hex()
    
    def decrypt(self, data) -> bytes:
        """decrypt data with self.key"""
        data = data if isinstance(data, bytes) else data.encode()
        try:
            data = bytes.fromhex(data.decode())
        except:
            pass

        assert len(data) <= len(self.key), "Key must be at least as long as data"
        
        chars = []

        for i in range(len(data)):
            char = data[i]
            key_char = self.key[i]
            final_char = (char - key_char) % 256
            chars.append(final_char)
        
        result = bytes(chars)
        return result
    
    def generate_key(self, key_length) -> bytes:
        """generate a true random vigenere key and return it"""
        return os.urandom(key_length)
