"""
One-time migration: backfill purchases.created_by

Run this ONCE, after pulling the updated app.py (which adds the
created_by column) and BEFORE relying on the new per-user ownership
checks. It assigns every existing purchase with no owner to the
first user ever registered (lowest id in the users table).

Usage:
    python migrate_purchase_ownership.py

Safe to run more than once — it only touches rows where
created_by IS NULL, so a second run is a no-op.
"""

import os
import sqlite3

DATABASE = os.path.join(os.path.dirname(__file__), "database.db")


def main():
    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    # Make sure the column exists (app.py's initialize_database() adds
    # it too, but this script can run standalone against an older db).
    try:
        cursor.execute(
            "ALTER TABLE purchases ADD COLUMN created_by INTEGER"
        )
        connection.commit()
        print("Added created_by column to purchases table.")
    except sqlite3.OperationalError:
        # Column already exists — fine.
        pass

    cursor.execute("SELECT COUNT(*) FROM purchases WHERE created_by IS NULL")
    orphaned_count = cursor.fetchone()[0]

    if orphaned_count == 0:
        print("Nothing to migrate — every purchase already has an owner.")
        connection.close()
        return

    cursor.execute("SELECT id, name, email FROM users ORDER BY id ASC LIMIT 1")
    first_user = cursor.fetchone()

    if first_user is None:
        print(
            "No users exist yet in the users table, so there's no one to "
            "assign these purchases to. Register at least one account "
            "first, then re-run this script."
        )
        connection.close()
        return

    first_user_id, first_user_name, first_user_email = first_user

    cursor.execute(
        "UPDATE purchases SET created_by = ? WHERE created_by IS NULL",
        (first_user_id,),
    )
    connection.commit()

    print(
        f"Assigned {orphaned_count} existing purchase(s) to "
        f"{first_user_name} ({first_user_email}), user id {first_user_id}."
    )

    connection.close()


if __name__ == "__main__":
    main()