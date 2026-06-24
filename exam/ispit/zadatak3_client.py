from kurs.network import connect_retry

conn = connect_retry(12345)

conn.close()
