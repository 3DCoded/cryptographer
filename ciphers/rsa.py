import binascii
import math
import secrets
from types import GeneratorType

from cryptographer.util import truncate


class RSAKey:
    """
    Secure RSA Cryptography

    Usage: 
        >>> rsa = RSAKey() # You could say, RSAKey(key_length=KEY_LENGTH)
        >>> encrypted = rsa.encrypt('hello world') # also works with b'hello world'
        >>> encrypted
        b'\x00\xb8Gd\x0e\x80\xc4\x01w\xfa#\xa8\x82\x19'
        >>> decrypted = rsa.decrypt(encrypted)
        >>> decrypted
        b'hello world'
        >>> encrypt_generator = rsa.encrypt_generator('hello world') # also works with b'hello world'
        >>> for chunk in encrypt_generator:
                print(chunk)
        b'\x00\xb8Gd\x0e\x80\xc4'
        b'\x01w\xfa#\xa8\x82\x19'
        >>> decrypt_generator = rsa.decrypt_generator(encrypted) # WARNING: decrypt_generator will remove spaces and null characters (\x00)
        >>> for chunk in decrypt_generator:
                print(chunk)
        b'hello'
        b'world'
    
    Pickling:
        >>> import pickle
        >>> pickle.dump(rsa, open('rsa.dat', 'wb'))
    
    Copying:
        >>> rsa2 = rsa.copy()
    """

    def __init__(self, key_length=10**8, keys=None) -> None:
        if keys is None:
            self.pubkey, self.privkey, self.composite = self.generate_keys(key_length)
        else:
            self.pubkey, self.privkey, self.composite = keys
        self.keys = self.pubkey, self.privkey, self.composite
    
    def __getstate__(self) -> dict:
        """Prepare self for pickling."""
        return {
            'keys': self.keys
        }
    
    def __setstate__(self, data) -> None:
        """Prepare self for unpickling."""
        self.pubkey, self.privkey, self.composite = data.get('keys')

    def __repr__(self) -> str:
        """return repr(self)"""
        return f'<RSAKey pubkey={truncate(str(self.pubkey))} privkey={truncate(str(self.privkey))} composite={truncate(str(self.composite))}>'
    
    __str__ = __repr__
    __str__.__doc__ = """return str(self)"""

    def get_public(self) -> tuple:
        """return self's public keys"""
        return (self.public, self.composite)
    
    def get_private(self) -> tuple:
        """return self's private keys"""
        return (self.private, self.composite)
    
    def set_public(self, public) -> None:
        """set self's public key to public"""
        self.public, self.composite = public
    
    def set_private(self, private) -> None:
        """set self's private key to private"""
        self.private, self.composite = private
    
    def copy(self):
        """return a copy of self"""
        return RSAKey(keys=self.keys)
    
    def _isprime(self, n, k=30) -> bool:
        """internal function - return whether or not n is prime"""
        if n <= 3:
            return n == 2 or n == 3
        n1 = n-1
        s, d = 0, n1
        while not d & 1:
            s, d = s + 1, d >> 1
        assert 2 ** s * d == n1 and d & 1

        for _ in range(k):
            a = secrets.randbelow(n1) + 2
            x = pow(a, d, n)
            if x in (1, n1):
                continue
            for _ in range(s - 1):
                x = x ** 2 % n
                if x == 1:
                    return False
                if x == n1:
                    break
            else:
                return False
        return True

    def _randprime(self, num) -> int:
        """internal function - return true random prime number"""
        prime = 1
        while not self._isprime(prime):
            prime = secrets.randbelow(num) + 1
        return prime
    
    def _multinv(self, mod, var) -> int:
        """internal function - return the multiplicative inverse"""
        x, lx = 0, 1
        a, b = mod, var
        while b:
            a, q, b = b, a // b, a % b
            x, lx = lx - q * x, x
        result = (1 - lx * mod) // var
        if result < 0:
            result += mod
        assert 0 <= result < mod and var * result % mod == 1
        return result
    
    def generate_keys(self, key_length) -> tuple:
        """generate and return true random RSA Keys in format (public, private, composite)"""
        prime1 = self._randprime(key_length)
        prime2 = self._randprime(key_length)
        composite = prime1 * prime2
        totient = (prime1 - 1) * (prime2 - 1)
        
        private = None
        while 1:
            private = secrets.randbelow(totient) + 1
            if math.gcd(private, totient) == 1:
                break
        public = self._multinv(totient, private)

        assert public * private % totient == math.gcd(public, totient) == math.gcd(private, totient) == 1
        assert pow(pow(1234567, public, composite), private, composite) == 1234567

        return public, private, composite
    
    def encrypt_generator(self, data) -> GeneratorType:
        """encrypt data - return generator"""
        chunksize = int(math.log(self.composite, 256))
        outchunk = chunksize + 1
        outfmt = '%%0%dx' % (outchunk* 2,)
        data = data if isinstance(data, bytes) else data.encode()
        for start in range(0, len(data), chunksize):
            chunk = data[start:start+chunksize]
            chunk += b'\x00'* (chunksize - len(chunk))
            plain = int(binascii.hexlify(chunk), 16)
            coded = pow(plain, self.pubkey, self.composite)
            bcoded = binascii.unhexlify((outfmt % coded).encode())
            yield bcoded

    def decrypt_generator(self, data) -> GeneratorType:
        """decrypt data - return generator"""
        chunksize = int(math.log(self.composite, 256))
        outchunk = chunksize + 1
        outfmt = '%%0%dx' % (chunksize * 2,)
        num = int(len(data) / outchunk)
        for start in range(0, len(data), outchunk):
            bcoded = data[start:start+outchunk]
            coded = int(binascii.hexlify(bcoded), 16)
            plain = pow(coded, self.privkey, self.composite)
            chunk = binascii.unhexlify((outfmt % plain).encode())
            yield chunk.rstrip(b'\x00')
    
    def encrypt(self, data) -> bytes:
        """encrypt data"""
        chunksize = int(math.log(self.composite, 256))
        outchunk = chunksize + 1
        outfmt = '%%0%dx' % (outchunk* 2,)
        data = data if isinstance(data, bytes) else data.encode()
        result = []
        for start in range(0, len(data), chunksize):
            chunk = data[start:start+chunksize]
            chunk += b'\x00'* (chunksize - len(chunk))
            plain = int(binascii.hexlify(chunk), 16)
            coded = pow(plain, self.pubkey, self.composite)
            bcoded = binascii.unhexlify((outfmt % coded).encode())
            result.append(bcoded)
        

        result = b''.join(result)
        return result
    
    def decrypt(self, data) -> bytes:
        """decrypt data"""
        chunksize = int(math.log(self.composite, 256))
        outchunk = chunksize + 1
        outfmt = '%%0%dx' % (chunksize * 2,)
        result = []
        for start in range(0, len(data), outchunk):
            bcoded = data[start:start+outchunk]
            coded = int(binascii.hexlify(bcoded), 16)
            plain = pow(coded, self.privkey, self.composite)
            chunk = binascii.unhexlify((outfmt % plain).encode())
            result.append(chunk)

        return b''.join(result).rstrip(b'\x00')
