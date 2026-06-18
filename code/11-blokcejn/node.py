"""P2P čvor igračkog blokčejna.

Pokretanje (podrazumevano, bezbedno — samo lokalni računar):

    python node.py <index> <n>                 # sluša na 127.0.0.1, index = 1..n

Za rad na više računara, eksplicitno biraš izloženost i daješ datoteku sa
adresama (red "host port" po čvoru, redom 1..n):

    python node.py <index> <n> --lan    --peers peers.txt   # vidljiv na LAN-u
    python node.py <index> <n> --public --peers peers.txt   # vidljiv svuda (0.0.0.0)

--lan i --public traže potvrdu, jer mreža koristi kurs.network (pickle preko
običnog TCP-a): BEZ šifrovanja i autentifikacije, pa svako ko dođe do porta može
da izvrši proizvoljan kod. Bezbedan način za rad preko mreže je SSH tunel ili VPN.

Čvor je jednonitni: u krug kopa porciju nonce-ova, pa osmotri mrežu (select).
Gossip je jednostavan — kad se pojavi duži ispravan lanac, čvor ga preuzme i
prosledi dalje. Transakcije se šire na isti način i skupljaju u mempool.
"""
import argparse
import select
import socket
import sys

from kurs.network import Listener, connect_retry
import block as blk
import chain as ch
import transaction as tx
from wallet import Wallet
from params import P2P_BASE, CLIENT_BASE, REWARD, MINE_BATCH, node_keys


def localhost_addrs(n):
    return {j: ("127.0.0.1", P2P_BASE + j) for j in range(1, n + 1)}


def load_addrs(path, n):
    addrs = {}
    with open(path) as f:
        for j, line in enumerate(l for l in f if l.strip()):
            host, port = line.split()
            addrs[j + 1] = (host, int(port))
    return addrs


def connect_peers(index, addrs, bind_host):
    """Full-mesh kao kurs.network.connect_mesh, ali sa eksplicitnim adresama
    (radi i preko više računara). Sluša na bind_host, a adrese iz `addrs`
    koristi za izlazne veze. Pozovi veće indekse, prihvati manje."""
    listener = Listener(host=bind_host, port=addrs[index][1])
    listener.start()
    peers = {}
    for j in sorted(addrs):
        if j > index:
            h, p = addrs[j]
            conn = connect_retry(p, host=h)
            conn.send(index)
            peers[j] = conn
    for _ in range(sum(1 for j in addrs if j < index)):
        conn, _ = listener.accept()
        peers[conn.recv()] = conn
    return listener, peers


class Node:
    def __init__(self, index, addrs, bind_host="127.0.0.1", mine=True):
        self.index = index
        self.addrs = addrs
        self.mine = mine
        self.wallet = Wallet(index)
        self.chain = ch.Blockchain.fresh()
        self.mempool = []
        self.listener, self.peers = connect_peers(index, addrs, bind_host)
        self.client = Listener(host=bind_host, port=CLIENT_BASE + index)
        self.client.start()
        self._rebuild_template()
        self._log(f"povezan sa {len(self.peers)} čvorova, kopam={mine}")

    def _log(self, msg):
        print(f"čvor {self.index}: {msg}", flush=True)

    # --- lanac / mempool ----------------------------------------------------
    def _rebuild_template(self):
        cb = tx.make_coinbase(self.chain.height + 1, self.wallet.t_pub, REWARD)
        trial, good = self.chain.state.clone(), []
        for t in self.mempool:
            try:
                trial.apply_tx(t)
                good.append(t)
            except ValueError:
                pass
        self.template = blk.make_block(self.chain.height + 1, self.chain.tip, [cb] + good)

    def _refresh_mempool(self):
        self.mempool = [t for t in self.mempool if self.chain.accepts(t)]

    def _adopt(self, blocks):
        if len(blocks) <= len(self.chain.blocks):
            return False
        try:
            cand = ch.Blockchain(blocks)
        except ValueError:
            return False
        if cand.height <= self.chain.height:
            return False
        self.chain = cand
        self._refresh_mempool()
        self._rebuild_template()
        self._log(f"preuzeo duži lanac, visina {self.chain.height}")
        return True

    # --- mreža --------------------------------------------------------------
    def _broadcast(self, msg):
        for conn in list(self.peers.values()):
            try:
                conn.send(msg)
            except OSError:
                pass

    def _handle(self, msg, conn=None):
        kind = msg[0]
        if kind == "chain":
            if self._adopt(msg[1]):
                self._broadcast(("chain", self.chain.blocks))
        elif kind == "tx":
            t = msg[1]
            if t not in self.mempool and self.chain.accepts(t):
                self.mempool.append(t)
                self._rebuild_template()
                self._broadcast(("tx", t))
        elif kind == "pay_t" and conn is not None:
            self._pay(conn, lambda: self.wallet.pay_transparent(
                self.chain, node_keys(msg[1])["t_pub"], msg[2]))
        elif kind == "pay_z" and conn is not None:
            self._pay(conn, lambda: self.wallet.pay_shielded(
                self.chain, node_keys(msg[1])["z_pub"], msg[2]))
        elif kind == "mine" and conn is not None:        # uključi/isključi kopanje
            self.mine = msg[1]
            conn.send(("ok", self.mine))
        elif kind == "query" and conn is not None:
            conn.send(self.status())

    def _pay(self, conn, build):
        try:
            t = build()
            self._handle(("tx", t))
            conn.send(("ok", tx.txid(t).hex()))
        except Exception as e:                       # noqa: BLE001 (igračka)
            conn.send(("err", str(e)))

    def status(self):
        return {
            "index": self.index,
            "height": self.chain.height,
            "tip": self.chain.tip.hex(),
            "t_balance": self.wallet.transparent_balance(self.chain),
            "z_balance": self.wallet.shielded_balance(self.chain),
        }

    # --- glavna petlja ------------------------------------------------------
    def run(self):
        socks = {conn.sock: conn for conn in self.peers.values()}
        while True:
            if self.mine:
                for _ in range(MINE_BATCH):
                    if blk.valid_pow(self.template):
                        self.chain = ch.Blockchain(self.chain.blocks + [self.template])
                        self._refresh_mempool()
                        self._log(f"iskopao blok, visina {self.chain.height}")
                        self._broadcast(("chain", self.chain.blocks))
                        self._rebuild_template()
                        break
                    self.template["nonce"] += 1

            timeout = 0 if self.mine else 0.2
            readable, _, _ = select.select(list(socks) + [self.client.sock], [], [], timeout)
            for s in readable:
                if s is self.client.sock:
                    conn, _ = self.client.accept()
                    msg = conn.recv()
                    if msg is not None:
                        self._handle(msg, conn)
                    conn.close()
                else:
                    msg = socks[s].recv()
                    if msg is None:
                        socks.pop(s)
                    else:
                        self._handle(msg, socks[s])


RED, RESET = "\033[91m", "\033[0m"


def detect_lan_ip():
    """IP adresa kojom ovaj računar izlazi na mrežu (obično 192.168.x.x)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))     # UDP „connect” ne šalje pakete
        return s.getsockname()[0]
    finally:
        s.close()


def warn_and_confirm(mode, bind_host, skip_prompt):
    where = (f"na lokalnoj mreži — dostupan SVAKOM uređaju na LAN-u ({bind_host})"
             if mode == "lan" else
             "na svim interfejsima (0.0.0.0) — potencijalno dostupan sa CELOG INTERNETA")
    for line in [
        "!!! UPOZORENJE !!!",
        f"Čvor će slušati {where}.",
        "Mreža koristi pickle preko običnog TCP-a: BEZ šifrovanja i BEZ autentifikacije.",
        "Svako ko dođe do porta može da IZVRŠI PROIZVOLJAN KOD na ovoj mašini.",
        "Bezbedno preko mreže: koristi SSH tunel ili VPN, a ne ovo direktno.",
    ]:
        print(RED + line + RESET, file=sys.stderr)
    if skip_prompt:
        print(RED + "(potvrda preskočena zbog --yes)" + RESET, file=sys.stderr)
        return
    try:
        answer = input("Da li ste sigurni? Otkucajte 'yes' za nastavak: ").strip().lower()
    except EOFError:
        answer = ""
    if answer != "yes":
        print("Prekinuto.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="P2P čvor igračkog blokčejna")
    ap.add_argument("index", type=int, help="indeks čvora (1..n)")
    ap.add_argument("n", type=int, help="ukupan broj čvorova")
    group = ap.add_mutually_exclusive_group()
    group.add_argument("--lan", action="store_true",
                       help="sluša na lokalnoj (192.168.x.x) adresi — vidljiv na LAN-u")
    group.add_argument("--public", action="store_true",
                       help="sluša na svim interfejsima (0.0.0.0) — može biti vidljiv sa interneta")
    ap.add_argument("--peers", metavar="DATOTEKA",
                    help="adrese čvorova (red 'host port' po čvoru); obavezno uz --lan/--public")
    ap.add_argument("--yes", action="store_true", help="preskoči potvrdu izloženosti (za skripte)")
    args = ap.parse_args()

    if args.lan or args.public:
        if not args.peers:
            ap.error("--lan/--public zahtevaju --peers datoteku sa adresama čvorova")
        bind_host = detect_lan_ip() if args.lan else "0.0.0.0"
        warn_and_confirm("lan" if args.lan else "public", bind_host, args.yes)
        addrs = load_addrs(args.peers, args.n)
    else:
        bind_host = "127.0.0.1"
        addrs = load_addrs(args.peers, args.n) if args.peers else localhost_addrs(args.n)

    Node(args.index, addrs, bind_host).run()
