import pickle
import socket
import struct
import time


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


def connect_retry(port, host="127.0.0.1", timeout=10.0):
    """Kao ClientConnection.connect, ali ponavlja dok se server ne podigne
    (korisno kada klijent krene pre nego što server počne da sluša)."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            return ClientConnection.connect(host, port)
        except ConnectionRefusedError:
            if time.monotonic() > deadline:
                raise
            time.sleep(0.05)


def connect_mesh(index, n, base_port=12344, timeout=10.0):
    """Uspostavlja potpuno povezanu (full mesh) mrežu između n učesnika, bez
    niti. Svaki učesnik prvo otvori svoj listener, zatim pozove sve učesnike sa
    većim indeksom (veza se prihvata u TCP backlog i pre poziva accept, pošto su
    svi već u listen stanju), a prihvati veze od svih sa manjim indeksom. Indeks
    se šalje kao handshake da bi obe strane znale ko je ko.

    Vraća (listener, peers) gde je peers rečnik {j: Connection} za svako j != i.
    Listener ostaje otvoren (npr. za kasnije posluživanje klijenata)."""
    listener = Listener(port=base_port + index)
    listener.start()

    peers = {}
    # Pozovi sve sa većim indeksom (njihov listener je već aktivan).
    for j in range(index + 1, n + 1):
        conn = connect_retry(base_port + j, timeout=timeout)
        conn.send(index)
        peers[j] = conn

    # Prihvati veze od svih sa manjim indeksom.
    for _ in range(index - 1):
        conn, _ = listener.accept()
        peers[conn.recv()] = conn

    return listener, peers
