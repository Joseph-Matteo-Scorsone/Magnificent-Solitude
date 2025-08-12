import sqlite3
import pandas as pd

# Visualize .db file
conn = sqlite3.connect('mag_sol_logging.db')

query = "SELECT * FROM mag_sol_logs"
df = pd.read_sql_query(query, conn)

conn.close()

print(df.head())
