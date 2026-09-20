# MoMoGuard Ghana

**Pause. Verify. Protect your money.**

MoMoGuard Ghana is a web-based consumer safety and fraud-awareness platform designed to help Ghanaian Mobile Money users identify, report, and understand suspicious phone numbers and potential payment-related scams.

It also includes a lightweight transaction-recording and verification workflow for buyers and sellers.

> **Important:** MoMoGuard is an awareness, reporting, and record-keeping platform. It does not process, control, or reverse Mobile Money transactions.

---

## The Problem

Mobile Money is widely used in Ghana for everyday payments, but users can encounter scams such as:

* Wrong-number scams
* Fake Mobile Money support
* Fake promotions
* Suspicious payment claims
* Fraudulent requests for money or personal information

When something goes wrong, users may also struggle to keep organized records of what happened.

---

## The Solution

MoMoGuard provides a simple workflow:

**STOP -> CHECK -> VERIFY -> REPORT**

Users can check a phone number before taking action, review previous reports, submit new reports, and access safety guidance.

---

## Features

### Phone Number Checking

Users can enter a Ghanaian phone number and see whether it has previously been reported.

The system provides:

* Number history
* Number of reports
* Scam type
* Description
* Risk score
* Risk level
* Safety guidance

A number with no reports is **not automatically considered safe**.

### Scam Reporting

Users can report suspicious numbers and select a scam category.

### Safety Awareness

MoMoGuard provides practical guidance to help users recognize suspicious calls, messages, payment requests, and social-engineering attempts.

### Dashboard

The dashboard provides an overview of reported activity, including:

* Total reports
* Unique reported numbers
* Scam categories
* Recent reports
* Purchase records

### Purchase Records

The prototype includes a buyer/seller transaction-recording workflow.

A purchase can contain:

* Item
* Amount
* Seller
* Buyer
* Transaction reference
* Payment evidence
* Verification status
* Delivery status

### Payment Verification

Transactions can move through controlled states:

**Pending -> Paid -> Delivered -> Completed**

### Dispute Tracking

A transaction can be marked as disputed and associated with a reason and supporting evidence.

### Buyer and Seller Views

Separate views allow transaction participants to see relevant purchase information and status.

---

## Risk Scoring

MoMoGuard currently uses a simple report-count-based risk model.

The prototype assigns increasing risk scores as the number of reports associated with a phone number increases.

This is an **experimental risk indicator**, not a guarantee that a number is fraudulent or safe.

---

## Technology Stack

**Backend**

* Python
* Flask
* Flask-WTF

**Frontend**

* HTML
* CSS
* Jinja2

**Database**

* SQLite

**Security**

* CSRF protection
* Environment-based production secret key
* Input validation

**Development and Deployment**

* Git
* GitHub
* Render
* Gunicorn

---

## Project Structure

```text
MoMoGuard-Ghana/
|
+-- backend/
|   +-- app.py
|   +-- database.py
|   +-- database.db
|   +-- requirements.txt
|   |
|   +-- static/
|   |   +-- style.css
|   |
|   +-- templates/
|       +-- base.html
|       +-- index.html
|       +-- check.html
|       +-- report.html
|       +-- dashboard.html
|       +-- safety.html
|       +-- purchase.html
|       +-- purchase_details.html
|       +-- buyer_view.html
|       +-- seller_view.html
|       +-- report_details.html
|       +-- success.html
|       +-- 404.html
|       +-- 500.html
|
+-- .gitignore
+-- README.md
```

---

## Running Locally

### 1. Clone the repository

```bash
git clone https://github.com/Ernie-kesse/MoMoGuard-Ghana-.git
cd MoMoGuard-Ghana
```

### 2. Create the virtual environment

```bash
python -m venv backend/.venv
```

### 3. Install dependencies

```bash
backend/.venv/Scripts/python.exe -m pip install -r backend/requirements.txt
```

### 4. Start the application

```bash
cd backend
.venv/Scripts/python.exe app.py
```

The application will run at:

```text
http://127.0.0.1:5000
```

---

## Security

MoMoGuard includes several basic security measures:

* CSRF protection for state-changing forms
* Production SECRET_KEY stored as an environment variable
* Input validation
* Controlled transaction status transitions
* Custom 404 and 500 error pages

For a production-scale application, additional security controls would be required.

---

## Deployment

The current prototype is deployed using:

* GitHub for source control
* Render for web hosting
* Gunicorn as the production WSGI server

Live application:

https://momoguard-ghana.onrender.com/

---

## Current Limitations

MoMoGuard is currently a prototype/MVP.

Important limitations include:

* SQLite is currently used for the database.
* The risk-scoring model is intentionally simple.
* The platform does not independently verify whether a submitted report is true.
* The platform does not process Mobile Money payments.
* The platform does not control or guarantee transaction reversals.
* The transaction workflow is a record-keeping prototype rather than a payment service.
* Production use would require stronger authentication, authorization, monitoring, abuse prevention, privacy controls, and a production-grade database.

---

## Future Improvements

Possible future development includes:

* PostgreSQL database
* User authentication and accounts
* Stronger report moderation
* Evidence uploads
* Better fraud-risk analysis
* Administrative moderation tools
* Improved privacy controls
* Notifications
* Better analytics and reporting
* Mobile-friendly progressive web application

---

## Project Goal

MoMoGuard Ghana is an exploration of how software can be used to address practical digital-safety problems in Ghana.

The project focuses on building trust through:

**Pause. Verify. Protect your money.**

---

## Developer

**Ernest Kesse**

Aspiring Software Developer

GitHub: https://github.com/Ernie-kesse

LinkedIn: https://www.linkedin.com/in/ernest-kesse-182520390/

---

## Disclaimer

MoMoGuard Ghana is an independent software project and is not an official MTN Mobile Money application or service.

The platform is intended for awareness, reporting, experimentation, and educational purposes.
