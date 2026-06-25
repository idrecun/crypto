import os
import zadatak3_rsa as rsa

d, (n, e) = rsa.generate_keys()
path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "zadatak3_keys.py")
open(path, "w").write("client_priv = %r\nclient_pub = %r\n" % ((d, n), (n, e)))
print("ok")
