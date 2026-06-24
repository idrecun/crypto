from kurs.network import connect_retry
import zadatak2_game as game

conn = connect_retry(12345)
game.play_first(conn, 2)
conn.close()
