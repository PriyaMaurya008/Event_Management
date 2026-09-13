import os


DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "priya1234",
    "database": "event_management"
}

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "priya.event12345")