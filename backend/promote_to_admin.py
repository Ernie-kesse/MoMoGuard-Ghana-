"""
One-time admin promotion script.

Grants admin privileges to one existing user, by email. There is no
way to become an admin through the web app itself — this is
deliberate, since a self-service "make me admin" checkbox would let
anyone grant themselves the ability to resolve disputes in their own
favor. Run this from the command line, which means it requires
direct access to the server/database, not just a web browser.

Usage:
    python promote_to_admin.py someone@example.com

To revoke admin instead, pass --revoke:
    python promote_to_admin.py someone@example.com --revoke
"""

import os
import sqlite3
import sys

DATABASE = os.path.join(os.path.dirname(__file__), "database.db")


def main():
    args = sys.argv[1:]

    if not args:
        print("Usage: python promote_to_admin.py someone@example.com [--revoke]")
        sys.exit(1)

    revoke = "--revoke" in args
    args = [a for a in args if a != "--revoke"]

    if len(args) != 1:
        print("Usage: python promote_to_admin.py someone@example.com [--revoke]")
        sys.exit(1)

    email = args[0].strip().lower()

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    cursor.execute(
        "SELECT id, name, email, is_admin FROM users WHERE email = ?",
        (email,),
    )
    user = cursor.fetchone()

    if user is None:
        print(f"No account found with email {email}.")
        connection.close()
        sys.exit(1)

    user_id, name, user_email, is_admin = user

    new_value = 0 if revoke else 1

    if is_admin == new_value:
        state = "already an admin" if is_admin else "already not an admin"
        print(f"{name} ({user_email}) is {state} — nothing to do.")
        connection.close()
        return

    cursor.execute(
        "UPDATE users SET is_admin = ? WHERE id = ?",
        (new_value, user_id),
    )
    connection.commit()
    connection.close()

    action = "revoked from" if revoke else "granted to"
    print(f"Admin access {action} {name} ({user_email}).")
    print("They'll need to log out and back in for the change to take effect.")


if __name__ == "__main__":
    main()