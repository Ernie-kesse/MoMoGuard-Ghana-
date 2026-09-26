"""
Seed script: adds one test scam report for local development.

This no longer creates the purchases table or its columns, or the
users table — those are owned entirely by app.py's
initialize_database(), which runs automatically every time the app
starts and is always kept current. Duplicating that schema here was
how this file drifted out of sync (it never picked up the users
table or the created_by column added for per-user purchase
ownership).

Run app.py at least once before this script, so the tables this
script depends on already exist.

Usage:
    python database.py
"""

import os
import sqlite3

DATABASE = os.path.join(
    os.path.dirname(__file__),
    "database.db"
)


def main():
    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    # Defensive only — app.py's initialize_database() is the source of
    # truth for this table's schema. This just makes sure the table
    # exists if someone runs this script standalone.
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scam_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            phone_number TEXT NOT NULL,
            scam_type TEXT NOT NULL,
            description TEXT,
            date_reported TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Insert the test report only if it does not already exist.
    cursor.execute(
        """
        SELECT id
        FROM scam_reports
        WHERE phone_number = ?
          AND scam_type = ?
          AND description = ?
        """,
        (
            "0550000000",
            "wrong-number scam",
            "Test scam report for MoMoGuard Ghana.",
        ),
    )

    if cursor.fetchone() is None:
        cursor.execute(
            """
            INSERT INTO scam_reports (
                phone_number,
                scam_type,
                description
            )
            VALUES (?, ?, ?)
            """,
            (
                "0550000000",
                "wrong-number scam",
                "Test scam report for MoMoGuard Ghana.",
            ),
        )
        print("Test scam report added.")
    else:
        print("Test scam report already exists — nothing to do.")

    connection.commit()
    connection.close()


if __name__ == "__main__":
    main()