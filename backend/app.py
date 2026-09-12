from datetime import datetime
import os
import sqlite3
from zoneinfo import ZoneInfo

from flask import Flask, flash, redirect, render_template, request


app = Flask(__name__)
app.secret_key = "momo-guard-secret-key"

DATABASE = os.path.join(os.path.dirname(__file__), "database.db")


# PHONE NUMBER HELPERS

def valid_ghana_phone(phone):
    valid_prefixes = (
        "020", "024", "025", "026", "027",
        "050", "053", "054", "055", "056", "057", "059",
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


# HOME

@app.route("/")
def home():
    return render_template("index.html")


# CHECK PHONE NUMBER

@app.route("/check", methods=["GET", "POST"])
def check():
    if request.method == "POST":
        phone = normalize_phone(request.form["phone"])

        if not valid_ghana_phone(phone):
            flash(
                "Invalid phone number. Please enter a Ghanaian number such as "
                "0241234567 or +233241234567.",
                "error",
            )
            return render_template("check.html", phone=phone)

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
                result = "🔴 High Risk: This number has been reported multiple times."
                risk_score = 90
            elif report_count >= 2:
                result = "🟠 Caution: This number has been reported more than once."
                risk_score = 60
            else:
                result = "⚠️ Warning: This number has been reported as a scam."
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
                "🟡 No report found for this number. This does not mean the "
                "number is safe. Stay cautious."
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


# REPORT SCAM

@app.route("/report", methods=["GET", "POST"])
def report():
    prefilled_phone = request.args.get("phone", "").strip()

    if request.method == "POST":
        phone = normalize_phone(request.form["phone"])
        scam_type = request.form["scam_type"].strip()
        description = request.form["description"].strip()

        if not scam_type:
            flash("Please select a scam type.", "error")
            return render_template("report.html", phone=phone)

        if len(description) < 10:
            flash(
                "Please provide at least 10 characters describing what happened.",
                "error",
            )
            return render_template("report.html", phone=phone)

        if not valid_ghana_phone(phone):
            flash(
                "Invalid phone number. Please enter a Ghanaian number such as "
                "0241234567 or +233241234567.",
                "error",
            )
            return render_template("report.html", phone=phone)

        connection = sqlite3.connect(DATABASE)
        cursor = connection.cursor()
        cursor.execute(
            """
            SELECT id
            FROM scam_reports
            WHERE phone_number = ? AND scam_type = ? AND description = ?
            """,
            (phone, scam_type, description),
        )

        if cursor.fetchone():
            connection.close()
            return "This report has already been submitted. Thank you for your vigilance."

        date_reported = datetime.now(ZoneInfo("Africa/Accra")).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        cursor.execute(
            """
            INSERT INTO scam_reports
                (phone_number, scam_type, description, date_reported)
            VALUES (?, ?, ?, ?)
            """,
            (phone, scam_type, description, date_reported),
        )
        connection.commit()
        connection.close()

        flash(
            "Your scam report has been submitted successfully. Thank you for "
            "helping to protect other MoMo users in Ghana.",
            "success",
        )
        return render_template("success.html", phone=phone)

    return render_template("report.html", phone=prefilled_phone)


# SAFETY

@app.route("/safety")
def safety():
    return render_template("safety.html")


# DASHBOARD

@app.route("/dashboard")
def dashboard():
    search = request.args.get("search", "").strip()
    scam_filter = request.args.get("scam_type", "").strip()
    if search:
        search = normalize_phone(search)

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    cursor.execute("SELECT COUNT(*) FROM scam_reports")
    total_reports = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(DISTINCT phone_number) FROM scam_reports")
    unique_numbers = cursor.fetchone()[0]

    category_counts = {}
    for category in ("Wrong-number scam", "Fake MoMo support", "Fake promotion"):
        cursor.execute(
            "SELECT COUNT(*) FROM scam_reports WHERE scam_type = ?", (category,)
        )
        category_counts[category] = cursor.fetchone()[0]

    query = """
        SELECT phone_number, scam_type, description, date_reported
        FROM scam_reports
    """
    parameters = []
    conditions = []
    if search:
        conditions.append("phone_number LIKE ?")
        parameters.append(f"%{search}%")
    if scam_filter:
        conditions.append("scam_type = ?")
        parameters.append(scam_filter)
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY date_reported DESC"
    if not search and not scam_filter:
        query += " LIMIT 10"

    cursor.execute(query, parameters)
    reports = cursor.fetchall()

    cursor.execute(
        """
        SELECT id, item, amount, seller_phone, buyer_phone,
               transaction_reference, transaction_date, transaction_time,
               payment_status, payment_evidence
        FROM purchases
        ORDER BY id DESC
        LIMIT 10
        """
    )
    purchases = cursor.fetchall()
    connection.close()

    current_date = datetime.now(ZoneInfo("Africa/Accra")).strftime("%d %B %Y")
    return render_template(
        "dashboard.html",
        total_reports=total_reports,
        unique_numbers=unique_numbers,
        wrong_number_reports=category_counts["Wrong-number scam"],
        fake_support_reports=category_counts["Fake MoMo support"],
        fake_promotion_reports=category_counts["Fake promotion"],
        reports=reports,
        purchases=purchases,
        search=search,
        scam_filter=scam_filter,
        current_date=current_date,
    )


# REPORT DETAILS

@app.route("/report/<phone>")
def report_details(phone):
    phone = normalize_phone(phone)
    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()
    cursor.execute(
        """
        SELECT phone_number, scam_type, description, date_reported
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


# CREATE PURCHASE

@app.route("/purchase", methods=["GET", "POST"])
def purchase():
    if request.method == "POST":
        item = request.form["item"].strip()
        amount_text = request.form["amount"].strip()
        seller_phone = normalize_phone(request.form["seller_phone"])
        buyer_phone = normalize_phone(request.form["buyer_phone"])
        transaction_reference = request.form["transaction_reference"].strip()
        payment_evidence = request.form["payment_evidence"].strip()

        if not item:
            flash("Please enter the item.", "error")
            return render_template("purchase.html")

        try:
            amount = float(amount_text)
            if amount <= 0:
                raise ValueError
        except ValueError:
            flash("Please enter a valid amount greater than GH₵0.", "error")
            return render_template("purchase.html")

        if not valid_ghana_phone(seller_phone):
            flash("Invalid seller phone number.", "error")
            return render_template("purchase.html")
        if not valid_ghana_phone(buyer_phone):
            flash("Invalid buyer phone number.", "error")
            return render_template("purchase.html")

        now = datetime.now(ZoneInfo("Africa/Accra"))
        connection = sqlite3.connect(DATABASE)
        cursor = connection.cursor()
        cursor.execute(
            """
            INSERT INTO purchases
                (item, amount, seller_phone, buyer_phone, transaction_reference,
                 transaction_date, transaction_time, payment_evidence)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
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
            ),
        )
        connection.commit()
        connection.close()
        flash("Purchase record created successfully!", "success")
        return render_template("purchase.html", success=True)

    return render_template("purchase.html")


def get_purchase(purchase_id):
    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()
    cursor.execute(
        """
        SELECT id, item, amount, seller_phone, buyer_phone,
               transaction_reference, transaction_date, transaction_time,
               payment_status, payment_evidence, payment_verification,dispute_reason,dispute_evidence
        FROM purchases
        WHERE id = ?
        """,
        (purchase_id,),
    )
    purchase_record = cursor.fetchone()
    connection.close()
    return purchase_record


# PURCHASE DETAILS

@app.route("/purchase/<int:purchase_id>")
def purchase_details(purchase_id):
    purchase_record = get_purchase(purchase_id)
    if purchase_record is None:
        return "Purchase record not found", 404
    return render_template("purchase_details.html", purchase=purchase_record)


# UPDATE PURCHASE STATUS

@app.route("/purchase/<int:purchase_id>/status", methods=["POST"])
def update_purchase_status(purchase_id):
    status = request.form["status"].strip()
    allowed_statuses = (
        "Pending", "Paid", "Delivered", "Completed", "Disputed", "Reversed"
    )
    if status not in allowed_statuses:
        flash("Invalid purchase status.", "error")
        return redirect(f"/purchase/{purchase_id}")

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()
    cursor.execute(
        """
        SELECT payment_verification, payment_status
        FROM purchases
        WHERE id = ?
        """,
        (purchase_id,),
    )
    purchase_record = cursor.fetchone()

    if purchase_record is None:
        connection.close()
        flash("Purchase record not found.", "error")
        return redirect("/dashboard")

    payment_verification, current_status = purchase_record
    if status == "Paid" and payment_verification != "Verified":
        connection.close()
        flash("Payment must be verified before the purchase can be marked as Paid.", "error")
        return redirect(f"/purchase/{purchase_id}")
    if status == "Delivered" and payment_verification != "Verified":
        connection.close()
        flash("Payment must be verified before the purchase can be marked as Delivered.", "error")
        return redirect(f"/purchase/{purchase_id}")
    if status == "Completed" and current_status != "Delivered":
        connection.close()
        flash(
            "The purchase must be marked as Delivered before it can be Completed.",
            "error"
        )
        return redirect(f"/purchase/{purchase_id}")

    cursor.execute(
        "UPDATE purchases SET payment_status = ? WHERE id = ?",
        (status, purchase_id),
    )
    connection.commit()
    connection.close()
    flash("Purchase status updated successfully!", "success")
    return redirect(f"/purchase/{purchase_id}")


# PAYMENT VERIFICATION

@app.route("/purchase/<int:purchase_id>/verification", methods=["POST"])
def update_payment_verification(purchase_id):
    verification = request.form["verification"].strip()
    allowed_verifications = (
        "Not verified", "Under review", "Verified", "Rejected"
    )
    if verification not in allowed_verifications:
        flash("Invalid payment verification status.", "error")
        return redirect(f"/purchase/{purchase_id}")

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    if verification == "Verified":
        new_status = "Paid"
    else:
        new_status = "Pending"

    cursor.execute(
        "UPDATE purchases SET payment_verification = ?, payment_status = ? WHERE id = ?",
        (verification, new_status, purchase_id),
        )
    connection.commit()
    connection.close()
    flash("Payment verification updated successfully!", "success")
    return redirect(f"/purchase/{purchase_id}")


# SELLER VIEW

@app.route("/seller/<int:purchase_id>")
def seller_view(purchase_id):
    purchase_record = get_purchase(purchase_id)
    if purchase_record is None:
        return "Purchase record not found", 404
    return render_template("seller_view.html", purchase=purchase_record)


# MARK PURCHASE AS DELIVERED

@app.route("/seller/<int:purchase_id>/delivered", methods=["POST"])
def mark_delivered(purchase_id):
    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()
    cursor.execute(
        "SELECT payment_verification FROM purchases WHERE id = ?",
        (purchase_id,),
    )
    purchase_record = cursor.fetchone()

    if purchase_record is None:
        connection.close()
        flash("Purchase record not found.", "error")
        return redirect("/dashboard")
    if purchase_record[0] != "Verified":
        connection.close()
        flash("The item cannot be marked as Delivered until payment is verified.", "error")
        return redirect(f"/seller/{purchase_id}")

    cursor.execute(
        "UPDATE purchases SET payment_status = 'Delivered' WHERE id = ?",
        (purchase_id,),
    )
    connection.commit()
    connection.close()
    flash("Purchase marked as Delivered!", "success")
    return redirect(f"/seller/{purchase_id}")


# BUYER VIEW

@app.route("/buyer/<int:purchase_id>")
def buyer_view(purchase_id):
    purchase_record = get_purchase(purchase_id)
    if purchase_record is None:
        return "Purchase record not found", 404
    return render_template("buyer_view.html", purchase=purchase_record)


# ERROR HANDLERS

@app.errorhandler(404)
def page_not_found(error):
    return render_template("404.html"), 404


@app.errorhandler(500)
def server_error(error):
    return render_template("500.html"), 500

@app.route("/purchase/<int:purchase_id>/dispute", methods=["POST"])
def dispute_purchase(purchase_id):

    reason = request.form.get("reason", "").strip()

    if len(reason) < 10:
        flash(
            "Dispute reason must be at least 10 characters.",
            "error"
        )
        return redirect(f"/purchase/{purchase_id}")

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    cursor.execute(
    "SELECT id FROM purchases WHERE id = ?",
    (purchase_id,)
    )
    purchase_record = cursor.fetchone()

    if purchase_record is None:
        connection.close()
        flash("Purchase record not found.", "error")
    return redirect("/dashboard")

    cursor.execute(
        """
        UPDATE purchases
        SET payment_status = 'Disputed',
            dispute_reason = ?
        WHERE id = ?
        """,
        (reason, purchase_id)
    )

    connection.commit()
    connection.close()

    flash(
        "⚠️ Purchase has been marked as disputed.",
        "success"
    )

    return redirect(f"/purchase/{purchase_id}")

@app.route("/purchase/<int:purchase_id>/dispute-evidence", methods=["POST"])
def add_dispute_evidence(purchase_id):

    evidence = request.form.get("evidence", "").strip()

    if len(evidence) < 10:
        flash(
            "Dispute evidence must be at least 10 characters.",
            "error"
        )
        return redirect(f"/purchase/{purchase_id}")

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    cursor.execute(
        """
        UPDATE purchases
        SET dispute_evidence = ?
        WHERE id = ?
        """,
        (evidence, purchase_id)
    )

    connection.commit()
    connection.close()

    flash(
        "📎 Dispute evidence has been saved.",
        "success"
    )

    return redirect(f"/purchase/{purchase_id}")

if __name__ == "__main__":
    app.run(debug=True)