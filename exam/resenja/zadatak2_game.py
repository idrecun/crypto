import hashlib
import random
import secrets

ACTIONS = ("napuni", "brani", "pucaj")
MAX = 3


def commit(action, nonce):
    return hashlib.sha256(action.encode() + nonce).digest()


def step(action, energy):
    return min(energy + 1, MAX) if action == "napuni" else energy - 1


def choose(my_e, opp_e, rng):
    if my_e == 0:
        return "napuni"
    if opp_e == 0:
        return "pucaj"
    return rng.choice(ACTIONS)


def resolve(my_action, my_e, opp_action, opp_e):
    my_hit = opp_action == "pucaj" and my_action != "brani"
    opp_hit = my_action == "pucaj" and opp_action != "brani"
    my_e = step(my_action, my_e)
    opp_e = step(opp_action, opp_e)
    print("ja=%s protivnik=%s | energija %d:%d" % (my_action, opp_action, my_e, opp_e))
    if my_hit and opp_hit:
        return "nereseno", my_e, opp_e
    if opp_hit:
        return "pobeda", my_e, opp_e
    if my_hit:
        return "poraz", my_e, opp_e
    return None, my_e, opp_e


def play_first(conn, seed):
    rng = random.Random(seed)
    my_e = opp_e = 0
    while True:
        action = choose(my_e, opp_e, rng)
        nonce = secrets.token_bytes(16)
        conn.send(commit(action, nonce))
        opp_c = conn.recv()
        conn.send((action, nonce))
        opp_action, opp_nonce = conn.recv()
        assert commit(opp_action, opp_nonce) == opp_c
        result, my_e, opp_e = resolve(action, my_e, opp_action, opp_e)
        if result is not None:
            print(result)
            return


def play_second(conn, seed):
    rng = random.Random(seed)
    my_e = opp_e = 0
    while True:
        opp_c = conn.recv()
        action = choose(my_e, opp_e, rng)
        nonce = secrets.token_bytes(16)
        conn.send(commit(action, nonce))
        opp_action, opp_nonce = conn.recv()
        conn.send((action, nonce))
        assert commit(opp_action, opp_nonce) == opp_c
        result, my_e, opp_e = resolve(action, my_e, opp_action, opp_e)
        if result is not None:
            print(result)
            return
