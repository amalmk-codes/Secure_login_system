# Secure Login System

## Overview

Secure Login System is a cybersecurity-focused web application developed using Flask. The project demonstrates secure authentication practices including password hashing, user session management, input validation, login activity monitoring, and Two-Factor Authentication (2FA).

This project was developed as part of a Cyber Security Internship to showcase practical implementation of authentication and web security concepts.

## Live Demo

https://secure-login-system-2-zrpm.onrender.com

## GitHub Repository

https://github.com/amalmk-codes/Secure_login_system

---

## Features

### Authentication

* User Registration
* User Login
* Secure Logout
* Session Management

### Security Features

* Password Hashing using Argon2
* SQL Injection Protection
* Input Validation
* CSRF Protection
* Secure Session Handling
* Account Lockout after Multiple Failed Attempts
* Login Activity Logging

### Two-Factor Authentication (2FA)

* QR Code Generation
* Google Authenticator Integration
* OTP Verification
* Time-Based One-Time Passwords (TOTP)

### Dashboard

* User Profile Information
* Security Status Monitoring
* Login Activity Tracking
* 2FA Status Display

---

## Technologies Used

### Backend

* Python
* Flask
* Flask-SQLAlchemy
* Flask-Login
* Flask-WTF

### Security

* Argon2 Password Hashing
* PyOTP
* QRCode

### Database

* SQLite

### Frontend

* HTML5
* CSS3
* Bootstrap 5

### Deployment

* Render

---

## Project Structure

```text
Secure_Login_System/
│
├── app.py
├── config.py
├── extensions.py
├── requirements.txt
│
├── models/
│   ├── user.py
│   └── login_log.py
│
├── templates/
│   ├── register.html
│   ├── login.html
│   ├── dashboard.html
│   ├── verify_otp.html
│   ├── setup_2fa.html
│   └── logs.html
│
├── static/
│   └── css/
│
├── utils/
│   ├── security.py
│   └── validators.py
│
└── tests/
```

---

## Installation

### Clone Repository

```bash
git clone https://github.com/amalmk-codes/Secure_login_system.git

cd Secure_login_system
```

### Create Virtual Environment

```bash
python -m venv venv
```

### Activate Virtual Environment

Windows

```bash
venv\Scripts\activate
```

Linux/Mac

```bash
source venv/bin/activate
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Run Application

```bash
python app.py
```

Open:

```text
http://127.0.0.1:5000
```

---

## Security Measures Implemented

### Password Security

* Passwords are never stored in plain text.
* Argon2 hashing is used to securely store credentials.

### SQL Injection Protection

* ORM-based database queries prevent SQL injection attacks.

### Session Security

* Secure user session management.
* Protected routes require authentication.

### Two-Factor Authentication

* OTP verification using authenticator applications.
* Additional layer of account protection.

### Brute Force Protection

* Account lockout after repeated failed login attempts.

---

## Learning Outcomes

Through this project, the following cybersecurity concepts were implemented and explored:

* Authentication Systems
* Password Hashing
* Multi-Factor Authentication
* Session Security
* Secure Database Access
* Web Application Security
* User Activity Monitoring

---

## Future Improvements

* Email Verification
* Password Reset via Email
* Role-Based Access Control
* OAuth Login (Google/GitHub)
* PostgreSQL Support
* Security Audit Dashboard

---

## Author

**AMAL M K**

B.Tech Computer Science and Engineering

Vidya Academy of Science and Technology

Cyber Security Internship Project – 2026

GitHub: https://github.com/amalmk-codes

---

## License

This project is developed for educational and internship purposes.
