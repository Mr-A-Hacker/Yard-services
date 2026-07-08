import unittest
from io import BytesIO
from unittest.mock import patch

from app import app


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


if __name__ == "__main__":
    unittest.main()
