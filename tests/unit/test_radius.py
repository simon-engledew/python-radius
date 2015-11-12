import unittest
import radius
from contextlib import closing
from multiprocessing.dummy import Pool
import struct
import socket
import select
import functools

@radius.lift(radius.join)
def read(connection):
    while True:
        r, w, x = select.select([connection], [], [], 0.1)
        if connection not in r: return
        yield connection.recv(4096)


def with_server(fn):
    @functools.wraps(fn)
    def decorated(self):
        pool = Pool(processes=1)
        with closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as server:
            server.bind(('127.0.0.1', 0))

            with radius.connect(server.getsockname(), 'secret') as client:
                return fn(
                    self,
                    client,
                    pool.apply_async(read, (server,))
                )
    return decorated

class TestRadius(unittest.TestCase):
    @with_server
    def test_ping(self, connection, result):
        connection.ping()

        packet = result.get(timeout=0.5)

        self.assertEqual(len(packet), 38)
        self.assertEqual(packet[0], struct.pack('!B', 12))

    @with_server
    def test_access_accept(self, connection, result):
        try:
            connection.authenticate('username', 'password')
        except IOError:
            pass

        packet = result.get(timeout=0.5)

        self.assertEqual(len(packet), 66)
        self.assertEqual(packet[0], struct.pack('!B', 1))

    @with_server
    def test_invalid_password(self, connection, result):
        self.assertRaises(AssertionError, connection.authenticate, 'username', 'password' + ('0' * 128))

