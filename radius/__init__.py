import os
import struct
import hashlib
import socket
import hmac
import select
import itertools
from contextlib import closing, contextmanager

def join(chunks):
    return ''.join(chunks)

def lift(partial):
    def decorator(fn):
        def decorated(*args, **kwargs):
            return partial(fn(*args, **kwargs))
        return decorated
    return decorator

class Pair(object):
    Head = '!B B'
    HeadSize = struct.calcsize(Head)

    def __init__(self, code, value):
        self.code = code
        self.value = value

    def __str__(self):
        return '{0}={1}'.format(self.code, self.value)

    @classmethod
    def unpack(cls, data):
        n = 0
        while n < len(data):
            code, length = struct.unpack(Pair.Head, data[n:n + Pair.HeadSize])
            yield Pair(code, data[n + Pair.HeadSize:n + length])
            n += length

    def pack(self):
        return struct.pack(Pair.Head, self.code, len(self.value) + Pair.HeadSize) + self.value

class Packet(object):
    Head, Tail = '!B B H 16s', '!B B 16s'
    HeadSize, TailSize = struct.calcsize(Head), struct.calcsize(Tail)

    def __init__(self, code, id, authenticator, *pairs):
        self.code = code
        self.id = id
        self.authenticator = authenticator
        self.pairs = pairs

    def __str__(self):
        return 'Packet({0}, id={1})[{2}]'.format(self.code, self.id, ', '.join(self.pairs))

    def __len__(self):
        return

    @classmethod
    def unpack(cls, secret, data):
        code, id, length, authenticator = struct.unpack(Packet.Head, data[:Packet.HeadSize])
        return Packet(code, *Pair.unpack(data[Packet.HeadSize:]), **{'id': id, 'authenticator': authenticator})

    def pack(self, secret):
        pairs = join(pair.pack() for pair in self.pairs)
        output = (
            struct.pack(
                Packet.Head,
                self.code,
                self.id,
                Packet.HeadSize + Packet.TailSize + len(pairs),
                self.authenticator
            ) +
            pairs
        )
        digest = hmac.new(
            secret,
            output + struct.pack(
                Packet.Tail,
                Radius.MESSAGE_AUTHENTICATOR,
                Packet.TailSize,
                ''
            )
        ).digest()
        return output + struct.pack(
            Packet.Tail,
            Radius.MESSAGE_AUTHENTICATOR,
            Packet.TailSize,
            digest
        )

class Radius(object):
    ACCESS_REQUEST = 1
    ACCESS_ACCEPT = 2
    ACCESS_REJECT = 3
    STATUS_SERVER = 12
    MESSAGE_AUTHENTICATOR = 80

    def __init__(self, connection, secret):
        self.connection = connection
        self.secret = secret

    @staticmethod
    @lift(join)
    def digest(secret, authenticator, password):
        if len(password) > 128:
          raise AssertionError('Password exceeds maximum length')

        previous = authenticator
        for n in xrange(0, len(password), 16):
            digest = hashlib.md5(secret + previous).digest()
            previous = join(chr(ord(a) ^ ord(b)) for a, b in itertools.izip_longest(digest, password[n:n + 16], fillvalue='\0'))
            yield previous

    @staticmethod
    def authenticator():
        return os.urandom(16)

    @classmethod
    @contextmanager
    def connect(cls, target, secret, timeout=3, retries=3):
        with closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as connection:
            connection.connect(target)

            yield cls(connection, secret)

    def ping(self):
        try:
            return Radius.ACCESS_ACCEPT == self(
                Packet(
                    Radius.STATUS_SERVER,
                    ord(os.urandom(1)),
                    Radius.authenticator(),
                )
            ).code
        except IOError:
            return False

    def authenticate(self, username, password):
        authenticator = Radius.authenticator()

        return Radius.ACCESS_ACCEPT == self(
            Packet(
                Radius.ACCESS_REQUEST,
                ord(os.urandom(1)),
                authenticator,
                Pair(1, username),
                Pair(2, Radius.digest(self.secret, authenticator, password))
            )
        ).code

    def __call__(self, outbound, timeout=3):
        self.connection.sendall(outbound.pack(self.secret))

        r, w, x = select.select([self.connection], [], [], timeout)

        if self.connection not in r:
            raise IOError('No response from host')

        response = self.connection.recv(4096)

        inbound = Packet.unpack(self.secret, response)

        if inbound.id != outbound.id:
            raise ValueError('Invalid packet id')

        if response[4:20] != hashlib.md5(response[0:4] + outbound.authenticator + response[20:] + self.secret).digest():
            raise ValueError('Illegal authenticator')

        return inbound

connect = Radius.connect
