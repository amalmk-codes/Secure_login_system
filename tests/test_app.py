import json
import unittest

from app import app, db
from models.user import User
from utils.security import hash_password
from utils.validators import validate_password


class AppTests(unittest.TestCase):
    def setUp(self):
        app.config.update(TESTING=True)
        self.client = app.test_client()
        with app.app_context():
            db.drop_all()
            db.create_all()

    def test_root_redirects_to_login(self):
        response = self.client.get("/", follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/login")

    def test_login_page_renders(self):
        response = self.client.get("/login")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Login", response.data)

    def test_register_page_renders(self):
        response = self.client.get("/register")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Create Account", response.data)

    def test_register_rejects_duplicate_email_case_insensitively(self):
        first_response = self.client.post(
            "/register",
            data={
                "username": "amal",
                "email": "amal@gmail.com",
                "password": "StrongPass123!",
            },
            follow_redirects=False,
        )
        self.assertEqual(first_response.status_code, 302)

        second_response = self.client.post(
            "/register",
            data={
                "username": "amal2",
                "email": "Amal@gmail.com",
                "password": "StrongPass123!",
            },
            follow_redirects=False,
        )
        self.assertEqual(second_response.status_code, 200)
        self.assertIn(b"That email is already registered.", second_response.data)

    def test_password_validator_requires_strong_password(self):
        self.assertFalse(validate_password("weakpass"))
        self.assertTrue(validate_password("StrongPass123!"))

    def test_account_locks_after_repeated_failed_logins(self):
        with app.app_context():
            user = User(username="lockme", email="lockme@example.com", password_hash="unused")
            user.failed_attempts = 4
            user.locked_until = None
            db.session.add(user)
            db.session.commit()

        response = self.client.post(
            "/login",
            data={"username": "lockme", "password": "wrongpass"},
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Account locked", response.data)

    def test_backup_code_can_finish_2fa_login(self):
        with app.app_context():
            user = User(
                username="backupuser",
                email="backup@example.com",
                password_hash="unused",
                otp_secret="JBSWY3DPEHPK3PXP",
                is_2fa_enabled=True,
                backup_codes=json.dumps([hash_password("RECOVERY-1")]),
            )
            db.session.add(user)
            db.session.commit()
            user_id = user.id

        with self.client.session_transaction() as session:
            session["pending_2fa_user_id"] = user_id

        response = self.client.post(
            "/verify-otp",
            data={"otp": "RECOVERY-1"},
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/dashboard")


if __name__ == "__main__":
    unittest.main()
