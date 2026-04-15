import pickle
import socket
import struct


class Connection:
    def __init__(self, sock):
        self.sock = sock

    def send(self, obj):
        data = pickle.dumps(obj)
        self.sock.sendall(struct.pack("!I", len(data)) + data)

    def recv(self):
        header = self._recvall(4)
        if header is None:
            return None
        size = struct.unpack("!I", header)[0]
        data = self._recvall(size)
        if data is None:
            return None
        return pickle.loads(data)

    def _recvall(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    def close(self):
        self.sock.close()


class Listener:
    def __init__(self, host="127.0.0.1", port=12345):
        self.host = host
        self.port = port
        self.sock = None

    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.sock.listen()

    def accept(self):
        client_sock, addr = self.sock.accept()
        return Connection(client_sock), addr

    def close(self):
        if self.sock is not None:
            self.sock.close()


class ClientConnection(Connection):
    @classmethod
    def connect(cls, host="127.0.0.1", port=12345):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        return cls(sock)
