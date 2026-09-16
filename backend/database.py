import os
import sqlite3

DATABASE = os.path.join(
    os.path.dirname(__file__),
    "database.db"
)


connection = sqlite3.connect(DATABASE)

cursor = connection.cursor()


# ============================================================
# Scam Reports Table
# ============================================================

cursor.execute("""
    CREATE TABLE IF NOT EXISTS scam_reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        phone_number TEXT NOT NULL,
        scam_type TEXT NOT NULL,
        description TEXT,
        date_reported TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
""")


# ============================================================
# Test Scam Report
# ============================================================

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


# ============================================================
# Purchase Records Table
# ============================================================

cursor.execute("""
    CREATE TABLE IF NOT EXISTS purchases (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        item TEXT NOT NULL,
        amount REAL NOT NULL,
        seller_phone TEXT NOT NULL,
        buyer_phone TEXT NOT NULL,
        transaction_reference TEXT,
        transaction_date TEXT NOT NULL,
        transaction_time TEXT NOT NULL,
        payment_status TEXT NOT NULL DEFAULT 'Pending'
    )
""")


# ============================================================
# Add New Purchase Columns
# ============================================================

# Payment evidence
try:
    cursor.execute(
        "ALTER TABLE purchases ADD COLUMN payment_evidence TEXT"
    )
except sqlite3.OperationalError:
    pass


# Payment verification
try:
    cursor.execute(
        """
        ALTER TABLE purchases
        ADD COLUMN payment_verification TEXT
        NOT NULL DEFAULT 'Not verified'
        """
    )
except sqlite3.OperationalError:
    pass


# Dispute reason
try:
    cursor.execute(
        "ALTER TABLE purchases ADD COLUMN dispute_reason TEXT"
    )
except sqlite3.OperationalError:
    pass


# Dispute evidence
try:
    cursor.execute(
        "ALTER TABLE purchases ADD COLUMN dispute_evidence TEXT"
    )
except sqlite3.OperationalError:
    pass


# ============================================================
# Save Changes
# ============================================================

connection.commit()

connection.close()


print("Database created successfully!")