import os
import shutil
import sqlite3
import tempfile
import unittest
from io import BytesIO
from unittest.mock import patch

import app as app_module

from app import app, get_db


class ServiceImageUploadTests(unittest.TestCase):
    def setUp(self):
        app.config.update(TESTING=True)
        self.client = app.test_client()
        with self.client.session_transaction() as session:
            session["admin_authenticated"] = True

    def test_admin_add_service_uses_b2_upload_for_image(self):
        with patch("app.save_upload_to_b2", return_value=("https://example.com/service.png", "png")) as save_mock:
            response = self.client.post(
                "/admin/add_service",
                data={
                    "name": "Test Service",
                    "price": "25.00",
                    "description": "Test description",
                    "image_url": "",
                    "image_file": (BytesIO(b"fake-image"), "service.png"),
                },
                content_type="multipart/form-data",
            )

        self.assertEqual(response.status_code, 302)
        save_mock.assert_called_once()

    def test_admin_edit_service_uses_b2_upload_for_image(self):
        with app.app_context():
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO services (name, price, description, image_url) VALUES (?, ?, ?, ?)",
                ("Existing Service", "15.00", "Existing description", ""),
            )
            service_id = cursor.lastrowid
            conn.commit()

        with patch("app.save_upload_to_b2", return_value=("https://example.com/service.png", "png")) as save_mock:
            response = self.client.post(
                f"/admin/edit_service/{service_id}",
                data={
                    "name": "Updated Service",
                    "price": "20.00",
                    "description": "Updated description",
                    "image_url": "",
                    "image_file": (BytesIO(b"fake-image"), "service.png"),
                },
                content_type="multipart/form-data",
            )

        self.assertEqual(response.status_code, 302)
        save_mock.assert_called_once()

    def test_request_service_handles_missing_required_fields(self):
        with app.app_context():
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (email, password_hash, phone) VALUES (?, ?, ?)",
                (f"requester-{os.urandom(4).hex()}@example.com", "hash", "1234567890"),
            )
            user_id = cursor.lastrowid
            conn.commit()

        with self.client.session_transaction() as session:
            session["_user_id"] = str(user_id)
            session["_fresh"] = True

        response = self.client.post("/request_service", data={})

        self.assertEqual(response.status_code, 302)

    def test_send_admin_notification_uses_webhook_when_configured(self):
        with patch.object(app_module, "NOTIFICATION_WEBHOOK_URL", "https://example.com/webhook"), patch.object(app_module, "urllib_request") as urllib_mock:
            class DummyResponse:
                status = 200

            urllib_mock.urlopen.return_value.__enter__.return_value = DummyResponse()
            app_module.send_admin_notification("Test subject", "Test body")

        urllib_mock.urlopen.assert_called_once()

    def test_send_sms_notification_uses_twilio_when_configured(self):
        with patch.object(app_module, "TWILIO_ACCOUNT_SID", "AC123"), patch.object(app_module, "TWILIO_AUTH_TOKEN", "token"), patch.object(app_module, "TWILIO_PHONE_NUMBER", "+15550000000"), patch.object(app_module, "SMS_TO_PHONE", "+15550000001"), patch.object(app_module, "requests") as requests_mock:
            requests_mock.post.return_value.raise_for_status.return_value = None
            app_module.send_sms_notification("Test SMS")

        requests_mock.post.assert_called_once()

    def test_upload_db_to_b2_includes_latest_wal_data(self):
        class DummyBucket:
            def __init__(self):
                self.uploaded_files = []

            def upload_local_file(self, local_file, file_name):
                self.uploaded_files.append((local_file, file_name))
                shutil.copyfile(local_file, os.path.join(self.temp_dir, "uploaded.db"))

        with tempfile.TemporaryDirectory() as temp_dir:
            dummy_bucket = DummyBucket()
            dummy_bucket.temp_dir = temp_dir
            db_path = os.path.join(temp_dir, "yard.db")

            with patch.object(app_module, "DB_LOCAL_PATH", db_path), patch.object(app_module, "B2_DB_PATH", "yard.db"), patch.object(app_module, "_app_has_b2", True), patch.object(app_module, "get_b2_bucket", return_value=dummy_bucket):
                with app.app_context():
                    conn = get_db()
                    conn.execute("PRAGMA journal_mode=WAL")
                    conn.execute("CREATE TABLE IF NOT EXISTS backup_test (value TEXT)")
                    conn.execute("INSERT INTO backup_test (value) VALUES (?)", ("persisted",))
                    conn.commit()
                    app_module.upload_db_to_b2()

            uploaded_db = os.path.join(temp_dir, "uploaded.db")
            self.assertTrue(os.path.exists(uploaded_db))
            uploaded_conn = sqlite3.connect(uploaded_db)
            try:
                row = uploaded_conn.execute("SELECT value FROM backup_test").fetchone()
                self.assertEqual(row[0], "persisted")
            finally:
                uploaded_conn.close()


if __name__ == "__main__":
    unittest.main()
