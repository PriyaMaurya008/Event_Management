import mysql.connector

connection = mysql.connector.connect(
    host="localhost",
    user="root",
    password="priya1234"
)

print("MySQL connected successfully!")

connection.close()