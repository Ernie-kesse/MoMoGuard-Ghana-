from datetime import datetime
from functools import wraps
import os
import sqlite3
from zoneinfo import ZoneInfo

from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_wtf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash


app = Flask(__name__)

# NOTE:
# Set a real SECRET_KEY in production.
app.secret_key = os.environ.get("SECRET_KEY", "dev-key-change-me")

# Protects every POST/PUT/PATCH/DELETE route against CSRF.
csrf = CSRFProtect(app)

# Session security
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
# Turn this on once the app is served over HTTPS in production — it stops
# the session cookie from ever being sent over plain HTTP. Leave it False
# for local http://localhost development, or the cookie won't be set at all.
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("SESSION_COOKIE_SECURE", "0") == "1"

DATABASE = os.path.join(os.path.dirname(__file__), "database.db")


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

def initialize_database():
    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    # USERS TABLE
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # SCAM REPORTS TABLE
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scam_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            phone_number TEXT NOT NULL,
            scam_type TEXT NOT NULL,
            description TEXT,
            date_reported TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # PURCHASES TABLE
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

    # Add newer purchase columns if they don't exist
    for column, definition in [
        ("payment_evidence", "TEXT"),
        ("payment_verification", "TEXT NOT NULL DEFAULT 'Not verified'"),
        ("dispute_reason", "TEXT"),
        ("dispute_evidence", "TEXT"),
        # Which logged-in user created this purchase record. NULL for
        # rows created before this column existed — run
        # migrate_purchase_ownership.py once to backfill those.
        ("created_by", "INTEGER"),
    ]:
        try:
            cursor.execute(
                f"ALTER TABLE purchases ADD COLUMN {column} {definition}"
            )
        except sqlite3.OperationalError:
            pass

    connection.commit()
    connection.close()


initialize_database()


# ============================================================
# AUTHENTICATION HELPERS
# ============================================================

def login_required(view_function):
    """
    Protect a route so only logged-in users can access it.
    """

    @wraps(view_function)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "error")
            return redirect(url_for("login"))

        return view_function(*args, **kwargs)

    return wrapped_view


# ============================================================
# PHONE NUMBER HELPERS
# ============================================================

def valid_ghana_phone(phone):
    valid_prefixes = (
        "020",
        "024",
        "025",
        "026",
        "027",
        "050",
        "053",
        "054",
        "055",
        "056",
        "057",
        "059",
    )

    return (
        phone.isdigit()
        and len(phone) == 10
        and phone.startswith(valid_prefixes)
    )


def normalize_phone(phone):
    phone = phone.strip().replace(" ", "")

    if phone.startswith("+233"):
        phone = "0" + phone[4:]

    return phone


# ============================================================
# PURCHASE STATE MACHINE
# ============================================================

ALLOWED_TRANSITIONS = {
    "Pending": {"Paid"},
    "Paid": {"Delivered", "Disputed"},
    "Delivered": {"Completed", "Disputed"},
    "Disputed": {
        "Pending",
        "Delivered",
        "Completed",
        "Reversed",
    },
    "Completed": set(),
    "Reversed": set(),
}

VERIFICATION_REQUIRED_FOR = {
    "Paid",
    "Delivered",
    "Completed",
}


def status_label(status):
    return status


# ============================================================
# HOME
# ============================================================

@app.route("/")
def home():
    return render_template("index.html")


# ============================================================
# REGISTER
# ============================================================

@app.route("/register", methods=["GET", "POST"])
def register():

    # If already logged in, don't show registration page.
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":

        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        # Validate name
        if not name:
            flash("Please enter your name.", "error")
            return render_template("register.html")

        # Validate email
        if not email or "@" not in email or "." not in email:
            flash("Please enter a valid email address.", "error")
            return render_template("register.html")

        # Validate password
        if len(password) < 8:
            flash(
                "Password must be at least 8 characters long.",
                "error",
            )
            return render_template("register.html")

        # Confirm password
        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return render_template("register.html")

        connection = sqlite3.connect(DATABASE)
        cursor = connection.cursor()

        # Check if email already exists
        cursor.execute(
            "SELECT id FROM users WHERE email = ?",
            (email,),
        )

        existing_user = cursor.fetchone()

        if existing_user:
            connection.close()
            flash(
                "An account with this email already exists.",
                "error",
            )
            return render_template("register.html")

        # Securely hash password
        password_hash = generate_password_hash(password)

        cursor.execute(
            """
            INSERT INTO users
                (name, email, password_hash)
            VALUES (?, ?, ?)
            """,
            (
                name,
                email,
                password_hash,
            ),
        )

        connection.commit()
        connection.close()

        flash(
            "Account created successfully. You can now log in.",
            "success",
        )

        return redirect(url_for("login"))

    return render_template("register.html")


# ============================================================
# LOGIN
# ============================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    # If already logged in, go to dashboard.
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not email or not password:
            flash(
                "Please enter your email and password.",
                "error",
            )
            return render_template("login.html")

        connection = sqlite3.connect(DATABASE)
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT id, name, email, password_hash
            FROM users
            WHERE email = ?
            """,
            (email,),
        )

        user = cursor.fetchone()
        connection.close()

        # User does not exist
        if user is None:
            flash(
                "Invalid email or password.",
                "error",
            )
            return render_template("login.html")

        user_id, user_name, user_email, password_hash = user

        # Check password against secure hash
        if not check_password_hash(password_hash, password):
            flash(
                "Invalid email or password.",
                "error",
            )
            return render_template("login.html")

        # Clear any previous session data
        session.clear()

        # Create logged-in session
        session["user_id"] = user_id
        session["user_name"] = user_name
        session["user_email"] = user_email

        flash(
            f"Welcome back, {user_name}!",
            "success",
        )

        return redirect(url_for("dashboard"))

    return render_template("login.html")


# ============================================================
# LOGOUT
# ============================================================

@app.route("/logout", methods=["POST"])
def logout():

    session.clear()

    flash(
        "You have been logged out successfully.",
        "success",
    )

    return redirect(url_for("home"))


# ============================================================
# CHECK PHONE NUMBER  (public — anyone can check a number)
# ============================================================

@app.route("/check", methods=["GET", "POST"])
def check():

    if request.method == "POST":

        phone = normalize_phone(
            request.form["phone"]
        )

        if not valid_ghana_phone(phone):
            flash(
                "Invalid phone number. Please enter a Ghanaian number "
                "such as 0241234567 or +233241234567.",
                "error",
            )

            return render_template(
                "check.html",
                phone=phone,
            )

        connection = sqlite3.connect(DATABASE)
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT scam_type, description
            FROM scam_reports
            WHERE phone_number = ?
            """,
            (phone,),
        )

        reports = cursor.fetchall()

        connection.close()

        if reports:

            report_count = len(reports)

            if report_count >= 5:
                result = (
                    "🔴 High Risk: This number has been "
                    "reported multiple times."
                )
                risk_score = 90

            elif report_count >= 2:
                result = (
                    "🟠 Caution: This number has been "
                    "reported more than once."
                )
                risk_score = 60

            else:
                result = (
                    "⚠️ Warning: This number has been "
                    "reported as a scam."
                )
                risk_score = 30

            if risk_score >= 80:
                risk_level = "HIGH RISK"

            elif risk_score >= 50:
                risk_level = "MEDIUM RISK"

            else:
                risk_level = "LOW RISK"

            scam_type, description = reports[0]

        else:

            result = (
                "🟡 No report found for this number. "
                "This does not mean the number is safe. "
                "Stay cautious."
            )

            scam_type = None
            description = None
            report_count = 0
            risk_score = 0
            risk_level = "NO REPORT"

        return render_template(
            "check.html",
            result=result,
            phone=phone,
            scam_type=scam_type,
            description=description,
            report_count=report_count,
            risk_score=risk_score,
            risk_level=risk_level,
        )

    return render_template("check.html")


# ============================================================
# REPORT SCAM  (public — anyone can file a report)
# ============================================================

@app.route("/report", methods=["GET", "POST"])
@login_required
def report():

    prefilled_phone = request.args.get(
        "phone",
        "",
    ).strip()

    if request.method == "POST":

        phone = normalize_phone(
            request.form["phone"]
        )

        scam_type = request.form[
            "scam_type"
        ].strip()

        description = request.form[
            "description"
        ].strip()

        if not scam_type:

            flash(
                "Please select a scam type.",
                "error",
            )

            return render_template(
                "report.html",
                phone=phone,
            )

        if len(description) < 10:

            flash(
                "Please provide at least 10 characters "
                "describing what happened.",
                "error",
            )

            return render_template(
                "report.html",
                phone=phone,
            )

        if not valid_ghana_phone(phone):

            flash(
                "Invalid phone number. Please enter a Ghanaian "
                "number such as 0241234567 or +233241234567.",
                "error",
            )

            return render_template(
                "report.html",
                phone=phone,
            )

        connection = sqlite3.connect(DATABASE)
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT id
            FROM scam_reports
            WHERE phone_number = ?
            AND scam_type = ?
            AND description = ?
            """,
            (
                phone,
                scam_type,
                description,
            ),
        )

        if cursor.fetchone():

            connection.close()

            return (
                "This report has already been submitted. "
                "Thank you for your vigilance."
            )

        date_reported = datetime.now(
            ZoneInfo("Africa/Accra")
        ).strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        cursor.execute(
            """
            INSERT INTO scam_reports
                (
                    phone_number,
                    scam_type,
                    description,
                    date_reported
                )
            VALUES (?, ?, ?, ?)
            """,
            (
                phone,
                scam_type,
                description,
                date_reported,
            ),
        )

        connection.commit()
        connection.close()

        flash(
            "Your scam report has been submitted successfully. "
            "Thank you for helping to protect other MoMo users in Ghana.",
            "success",
        )

        return render_template(
            "success.html",
            phone=phone,
        )

    return render_template(
        "report.html",
        phone=prefilled_phone,
    )


# ============================================================
# SAFETY  (public)
# ============================================================

@app.route("/safety")
def safety():
    return render_template("safety.html")


# ============================================================
# DASHBOARD  (requires login)
# ============================================================

@app.route("/dashboard")
@login_required
def dashboard():

    search = request.args.get(
        "search",
        "",
    ).strip()

    scam_filter = request.args.get(
        "scam_type",
        "",
    ).strip()

    if search:
        search = normalize_phone(search)

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    cursor.execute(
        "SELECT COUNT(*) FROM scam_reports"
    )

    total_reports = cursor.fetchone()[0]

    cursor.execute(
        """
        SELECT COUNT(DISTINCT phone_number)
        FROM scam_reports
        """
    )

    unique_numbers = cursor.fetchone()[0]

    category_counts = {}

    for category in (
        "Wrong-number scam",
        "Fake MoMo support",
        "Fake promotion",
    ):

        cursor.execute(
            """
            SELECT COUNT(*)
            FROM scam_reports
            WHERE scam_type = ?
            """,
            (category,),
        )

        category_counts[category] = cursor.fetchone()[0]

    query = """
        SELECT
            phone_number,
            scam_type,
            description,
            date_reported
        FROM scam_reports
    """

    parameters = []
    conditions = []

    if search:

        conditions.append(
            "phone_number LIKE ?"
        )

        parameters.append(
            f"%{search}%"
        )

    if scam_filter:

        conditions.append(
            "scam_type = ?"
        )

        parameters.append(
            scam_filter
        )

    if conditions:

        query += (
            " WHERE "
            + " AND ".join(conditions)
        )

    query += (
        " ORDER BY date_reported DESC"
    )

    if not search and not scam_filter:

        query += " LIMIT 10"

    cursor.execute(
        query,
        parameters,
    )

    reports = cursor.fetchall()

    cursor.execute(
        """
        SELECT
            id,
            item,
            amount,
            seller_phone,
            buyer_phone,
            transaction_reference,
            transaction_date,
            transaction_time,
            payment_status,
            payment_evidence
        FROM purchases
        WHERE created_by = ?
        ORDER BY id DESC
        LIMIT 10
        """,
        (session["user_id"],),
    )

    purchases = cursor.fetchall()

    connection.close()

    current_date = datetime.now(
        ZoneInfo("Africa/Accra")
    ).strftime(
        "%d %B %Y"
    )

    return render_template(
        "dashboard.html",
        total_reports=total_reports,
        unique_numbers=unique_numbers,
        wrong_number_reports=category_counts[
            "Wrong-number scam"
        ],
        fake_support_reports=category_counts[
            "Fake MoMo support"
        ],
        fake_promotion_reports=category_counts[
            "Fake promotion"
        ],
        reports=reports,
        purchases=purchases,
        search=search,
        scam_filter=scam_filter,
        current_date=current_date,
    )


# ============================================================
# REPORT DETAILS  (public — same audience as /check and /report)
# ============================================================

@app.route("/report/<phone>")
def report_details(phone):

    phone = normalize_phone(phone)

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            phone_number,
            scam_type,
            description,
            date_reported
        FROM scam_reports
        WHERE phone_number = ?
        ORDER BY date_reported DESC
        """,
        (phone,),
    )

    reports = cursor.fetchall()

    connection.close()

    return render_template(
        "report_details.html",
        phone=phone,
        reports=reports,
        report_count=len(reports),
    )


# ============================================================
# CREATE PURCHASE  (requires login)
# ============================================================

@app.route("/purchase", methods=["GET", "POST"])
@login_required
def purchase():

    if request.method == "POST":

        item = request.form[
            "item"
        ].strip()

        amount_text = request.form[
            "amount"
        ].strip()

        seller_phone = normalize_phone(
            request.form["seller_phone"]
        )

        buyer_phone = normalize_phone(
            request.form["buyer_phone"]
        )

        transaction_reference = request.form[
            "transaction_reference"
        ].strip()

        payment_evidence = request.form[
            "payment_evidence"
        ].strip()

        if not item:

            flash(
                "Please enter the item.",
                "error",
            )

            return render_template(
                "purchase.html"
            )

        try:

            amount = float(
                amount_text
            )

            if amount <= 0:
                raise ValueError

        except ValueError:

            flash(
                "Please enter a valid amount greater than GH₵0.",
                "error",
            )

            return render_template(
                "purchase.html"
            )

        if not valid_ghana_phone(
            seller_phone
        ):

            flash(
                "Invalid seller phone number.",
                "error",
            )

            return render_template(
                "purchase.html"
            )

        if not valid_ghana_phone(
            buyer_phone
        ):

            flash(
                "Invalid buyer phone number.",
                "error",
            )

            return render_template(
                "purchase.html"
            )

        now = datetime.now(
            ZoneInfo("Africa/Accra")
        )

        connection = sqlite3.connect(
            DATABASE
        )

        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO purchases
                (
                    item,
                    amount,
                    seller_phone,
                    buyer_phone,
                    transaction_reference,
                    transaction_date,
                    transaction_time,
                    payment_evidence,
                    created_by
                )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                item,
                amount,
                seller_phone,
                buyer_phone,
                transaction_reference,
                now.strftime("%Y-%m-%d"),
                now.strftime("%H:%M:%S"),
                payment_evidence,
                # purchase() is @login_required, so session["user_id"]
                # is always present here.
                session["user_id"],
            ),
        )

        connection.commit()
        connection.close()

        flash(
            "Purchase record created successfully!",
            "success",
        )

        return render_template(
            "purchase.html",
            success=True,
        )

    return render_template(
        "purchase.html"
    )


# ============================================================
# GET PURCHASE
# ============================================================

def get_purchase(purchase_id, owner_user_id):
    """
    Fetch a purchase only if it was created by owner_user_id.

    Deliberately returns None both when the purchase doesn't exist at
    all AND when it exists but belongs to someone else — the caller
    can't tell the two apart, and every call site already shows the
    same generic "Purchase record not found" message either way. That
    matters: a route that said "not found" for a missing ID but "not
    yours" for someone else's would let a logged-in user probe IDs
    and learn which purchases exist even without being able to open
    them.
    """

    connection = sqlite3.connect(
        DATABASE
    )

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            id,
            item,
            amount,
            seller_phone,
            buyer_phone,
            transaction_reference,
            transaction_date,
            transaction_time,
            payment_status,
            payment_evidence,
            payment_verification,
            dispute_reason,
            dispute_evidence
        FROM purchases
        WHERE id = ? AND created_by = ?
        """,
        (purchase_id, owner_user_id),
    )

    purchase_record = cursor.fetchone()

    connection.close()

    return purchase_record


# ============================================================
# PURCHASE DETAILS  (requires login)
# ============================================================

@app.route("/purchase/<int:purchase_id>")
@login_required
def purchase_details(purchase_id):

    purchase_record = get_purchase(
        purchase_id,
        session["user_id"],
    )

    if purchase_record is None:

        return (
            "Purchase record not found",
            404,
        )

    current_status = purchase_record[8]

    # Tell the template which actions are actually reachable from here,
    # so it stops offering buttons/options the backend will just reject.
    allowed_next_statuses = sorted(
        ALLOWED_TRANSITIONS.get(current_status, set())
    )
    can_dispute = "Disputed" in ALLOWED_TRANSITIONS.get(current_status, set())
    can_update_verification = current_status in {"Pending", "Paid"}

    return render_template(
        "purchase_details.html",
        purchase=purchase_record,
        allowed_next_statuses=allowed_next_statuses,
        can_dispute=can_dispute,
        can_update_verification=can_update_verification,
    )


# ============================================================
# UPDATE PURCHASE STATUS  (requires login)
# ============================================================

@app.route(
    "/purchase/<int:purchase_id>/status",
    methods=["POST"],
)
@login_required
def update_purchase_status(
    purchase_id
):

    status = request.form[
        "status"
    ].strip()

    if status not in ALLOWED_TRANSITIONS:

        flash(
            "Invalid purchase status.",
            "error",
        )

        return redirect(
            f"/purchase/{purchase_id}"
        )

    connection = sqlite3.connect(
        DATABASE
    )

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            payment_verification,
            payment_status
        FROM purchases
        WHERE id = ? AND created_by = ?
        """,
        (purchase_id, session["user_id"]),
    )

    purchase_record = cursor.fetchone()

    if purchase_record is None:

        connection.close()

        flash(
            "Purchase record not found.",
            "error",
        )

        return redirect(
            "/dashboard"
        )

    payment_verification, current_status = (
        purchase_record
    )

    if status not in ALLOWED_TRANSITIONS.get(
        current_status,
        set(),
    ):

        flash(
            f"Cannot move a purchase from "
            f"{current_status} to {status}.",
            "error",
        )

        connection.close()

        return redirect(
            f"/purchase/{purchase_id}"
        )

    if (
        status in VERIFICATION_REQUIRED_FOR
        and payment_verification != "Verified"
    ):

        connection.close()

        flash(
            f"Payment must be verified before "
            f"the purchase can be marked as {status}.",
            "error",
        )

        return redirect(
            f"/purchase/{purchase_id}"
        )

    cursor.execute(
        """
        UPDATE purchases
        SET payment_status = ?
        WHERE id = ? AND created_by = ?
        """,
        (
            status,
            purchase_id,
            session["user_id"],
        ),
    )

    connection.commit()
    connection.close()

    flash(
        "Purchase status updated successfully!",
        "success",
    )

    return redirect(
        f"/purchase/{purchase_id}"
    )


# ============================================================
# PAYMENT VERIFICATION  (requires login)
# ============================================================

@app.route(
    "/purchase/<int:purchase_id>/verification",
    methods=["POST"],
)
@login_required
def update_payment_verification(
    purchase_id
):

    verification = request.form[
        "verification"
    ].strip()

    allowed_verifications = (
        "Not verified",
        "Under review",
        "Verified",
        "Rejected",
    )

    if verification not in allowed_verifications:

        flash(
            "Invalid payment verification status.",
            "error",
        )

        return redirect(
            f"/purchase/{purchase_id}"
        )

    connection = sqlite3.connect(
        DATABASE
    )

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT payment_status
        FROM purchases
        WHERE id = ? AND created_by = ?
        """,
        (purchase_id, session["user_id"]),
    )

    row = cursor.fetchone()

    if row is None:

        connection.close()

        flash(
            "Purchase record not found.",
            "error",
        )

        return redirect(
            "/dashboard"
        )

    current_status = row[0]

    if current_status not in {
        "Pending",
        "Paid",
    }:

        connection.close()

        flash(
            f"Payment verification can no longer "
            f"be changed once a purchase is "
            f"{current_status}.",
            "error",
        )

        return redirect(
            f"/purchase/{purchase_id}"
        )

    new_status = (
        "Paid"
        if verification == "Verified"
        else "Pending"
    )

    cursor.execute(
        """
        UPDATE purchases
        SET
            payment_verification = ?,
            payment_status = ?
        WHERE id = ? AND created_by = ?
        """,
        (
            verification,
            new_status,
            purchase_id,
            session["user_id"],
        ),
    )

    connection.commit()
    connection.close()

    flash(
        "Payment verification updated successfully!",
        "success",
    )

    return redirect(
        f"/purchase/{purchase_id}"
    )


# ============================================================
# SELLER VIEW  (requires login)
# ============================================================

@app.route(
    "/seller/<int:purchase_id>"
)
@login_required
def seller_view(purchase_id):

    purchase_record = get_purchase(
        purchase_id,
        session["user_id"],
    )

    if purchase_record is None:

        return (
            "Purchase record not found",
            404,
        )

    # Matches the narrower check in mark_delivered(): only a Paid,
    # Verified purchase can be marked Delivered from this self-service
    # button, regardless of what ALLOWED_TRANSITIONS permits elsewhere.
    payment_verification, current_status = purchase_record[10], purchase_record[8]
    can_mark_delivered = (
        current_status == "Paid" and payment_verification == "Verified"
    )

    return render_template(
        "seller_view.html",
        purchase=purchase_record,
        can_mark_delivered=can_mark_delivered,
    )


# ============================================================
# MARK PURCHASE AS DELIVERED  (requires login)
# ============================================================

@app.route(
    "/seller/<int:purchase_id>/delivered",
    methods=["POST"],
)
@login_required
def mark_delivered(purchase_id):

    connection = sqlite3.connect(
        DATABASE
    )

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            payment_verification,
            payment_status
        FROM purchases
        WHERE id = ? AND created_by = ?
        """,
        (purchase_id, session["user_id"]),
    )

    purchase_record = cursor.fetchone()

    if purchase_record is None:

        connection.close()

        flash(
            "Purchase record not found.",
            "error",
        )

        return redirect(
            "/dashboard"
        )

    payment_verification, current_status = (
        purchase_record
    )

    # Deliberately narrower than ALLOWED_TRANSITIONS: this is the seller's
    # own self-service button, not the admin status dropdown. The full
    # transition table allows Disputed -> Delivered so that a *resolved*
    # dispute can move forward again, but that resolution should happen
    # deliberately via update_purchase_status on the dashboard — not be
    # something a seller can trigger by clicking "Mark as Delivered" while
    # a dispute is still open. So this route only fires from "Paid".
    if current_status != "Paid":

        connection.close()

        flash(
            f"Only a purchase that is Paid can be marked as Delivered "
            f"here. This purchase is currently {current_status} — "
            f"if it's under dispute, resolve the dispute from the "
            f"purchase record first.",
            "error",
        )

        return redirect(
            f"/seller/{purchase_id}"
        )

    if payment_verification != "Verified":

        connection.close()

        flash(
            "The item cannot be marked as Delivered "
            "until payment is verified.",
            "error",
        )

        return redirect(
            f"/seller/{purchase_id}"
        )

    cursor.execute(
        """
        UPDATE purchases
        SET payment_status = 'Delivered'
        WHERE id = ? AND created_by = ?
        """,
        (purchase_id, session["user_id"]),
    )

    connection.commit()
    connection.close()

    flash(
        "Purchase marked as Delivered!",
        "success",
    )

    return redirect(
        f"/seller/{purchase_id}"
    )


# ============================================================
# BUYER VIEW  (requires login)
# ============================================================

@app.route(
    "/buyer/<int:purchase_id>"
)
@login_required
def buyer_view(purchase_id):

    purchase_record = get_purchase(
        purchase_id,
        session["user_id"],
    )

    if purchase_record is None:

        return (
            "Purchase record not found",
            404,
        )

    return render_template(
        "buyer_view.html",
        purchase=purchase_record,
    )


# ============================================================
# DISPUTE PURCHASE  (requires login)
# ============================================================

@app.route(
    "/purchase/<int:purchase_id>/dispute",
    methods=["POST"],
)
@login_required
def dispute_purchase(purchase_id):

    reason = request.form.get(
        "reason",
        "",
    ).strip()

    if len(reason) < 10:

        flash(
            "Dispute reason must be at least "
            "10 characters.",
            "error",
        )

        return redirect(
            f"/purchase/{purchase_id}"
        )

    connection = sqlite3.connect(
        DATABASE
    )

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT payment_status
        FROM purchases
        WHERE id = ? AND created_by = ?
        """,
        (purchase_id, session["user_id"]),
    )

    purchase_record = cursor.fetchone()

    if purchase_record is None:

        connection.close()

        flash(
            "Purchase record not found.",
            "error",
        )

        return redirect(
            "/dashboard"
        )

    current_status = purchase_record[0]

    if "Disputed" not in ALLOWED_TRANSITIONS.get(
        current_status,
        set(),
    ):

        connection.close()

        flash(
            f"A purchase that is {current_status} "
            f"cannot be disputed.",
            "error",
        )

        return redirect(
            f"/purchase/{purchase_id}"
        )

    cursor.execute(
        """
        UPDATE purchases
        SET
            payment_status = 'Disputed',
            dispute_reason = ?
        WHERE id = ? AND created_by = ?
        """,
        (
            reason,
            purchase_id,
            session["user_id"],
        ),
    )

    connection.commit()
    connection.close()

    flash(
        "⚠️ Purchase has been marked as disputed.",
        "success",
    )

    return redirect(
        f"/purchase/{purchase_id}"
    )


# ============================================================
# ADD DISPUTE EVIDENCE  (requires login)
# ============================================================

@app.route(
    "/purchase/<int:purchase_id>/dispute-evidence",
    methods=["POST"],
)
@login_required
def add_dispute_evidence(
    purchase_id
):

    evidence = request.form.get(
        "evidence",
        "",
    ).strip()

    if len(evidence) < 10:

        flash(
            "Dispute evidence must be at least "
            "10 characters.",
            "error",
        )

        return redirect(
            f"/purchase/{purchase_id}"
        )

    connection = sqlite3.connect(
        DATABASE
    )

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT payment_status
        FROM purchases
        WHERE id = ? AND created_by = ?
        """,
        (purchase_id, session["user_id"]),
    )

    purchase_record = cursor.fetchone()

    if purchase_record is None:

        connection.close()

        flash(
            "Purchase record not found.",
            "error",
        )

        return redirect(
            "/dashboard"
        )

    if purchase_record[0] != "Disputed":

        connection.close()

        flash(
            "Dispute evidence can only be added "
            "to a purchase that is currently Disputed.",
            "error",
        )

        return redirect(
            f"/purchase/{purchase_id}"
        )

    cursor.execute(
        """
        UPDATE purchases
        SET dispute_evidence = ?
        WHERE id = ? AND created_by = ?
        """,
        (
            evidence,
            purchase_id,
            session["user_id"],
        ),
    )

    connection.commit()
    connection.close()

    flash(
        "📎 Dispute evidence has been saved.",
        "success",
    )

    return redirect(
        f"/purchase/{purchase_id}"
    )


# ============================================================
# ERROR HANDLERS
# ============================================================

@app.errorhandler(404)
def page_not_found(error):
    return render_template(
        "404.html"
    ), 404


@app.errorhandler(500)
def server_error(error):
    return render_template(
        "500.html"
    ), 500


# ============================================================
# RUN APPLICATION
# ============================================================

if __name__ == "__main__":
    app.run(debug=True)