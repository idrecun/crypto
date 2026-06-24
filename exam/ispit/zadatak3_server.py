from kurs.network import Listener

listener = Listener()
listener.start()
conn, _ = listener.accept()

conn.close()
listener.close()
