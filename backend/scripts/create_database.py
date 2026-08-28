"""One-time setup: creates the MySQL database itself (create_all only creates tables
inside an existing database). Run once before starting the API:

    python backend/scripts/create_database.py
"""

from __future__ import annotations

import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import pymysql

from app.config import settings


def main() -> None:
    connection = pymysql.connect(
        host=settings.db_host, port=settings.db_port,
        user=settings.db_user, password=settings.db_password,
    )
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                f"CREATE DATABASE IF NOT EXISTS `{settings.db_name}` "
                "CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
            )
        connection.commit()
        print(f"Database '{settings.db_name}' is ready.")
    finally:
        connection.close()


if __name__ == "__main__":
    main()
