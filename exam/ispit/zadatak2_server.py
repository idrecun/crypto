from kurs.network import Listener
import zadatak2_game as game

listener = Listener()
listener.start()
conn, _ = listener.accept()
game.play_second(conn, 1)
conn.close()
listener.close()
