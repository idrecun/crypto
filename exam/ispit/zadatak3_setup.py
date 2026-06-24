import os
import zadatak3_rsa as rsa

priv, pub = rsa.generate_keys()
path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "zadatak3_keys.py")
open(path, "w").write("client_priv = %r\nclient_pub = %r\n" % (priv, pub))
print("ok")
