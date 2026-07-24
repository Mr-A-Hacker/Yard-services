# Yard-services

## Render setup

This app stores the SQLite database locally in `yard.db` while the instance is running. To keep user accounts and bookings after a Render restart or redeploy, configure Backblaze B2 as the durable database backup. Uploaded service images, popup media, and background files continue to save under `static/uploads/`.

Add these environment variables in Render:

```bash
SECRET_KEY=your-long-random-secret
DB_LOCAL_PATH=yard.db
B2_BUCKET_NAME=yardservices-storage-2
B2_BUCKET_ID=6cb12b4a501892429bfe0716
B2_ENDPOINT_URL=https://s3.us-east-005.backblazeb2.com
B2_KEY_ID=your-backblaze-key-id
B2_APPLICATION_KEY=your-backblaze-application-key
B2_DB_OBJECT_KEY=yard.db
```

Do not commit real Backblaze application keys to the repository. Add them only as private Render environment variables.

## Notifications

To send service-request alerts to a chat bot or webhook-compatible endpoint, configure a webhook URL:

```bash
NOTIFICATION_WEBHOOK_URL=https://your-webhook-url
```

To send a phone SMS notification as well, configure Twilio:

```bash
TWILIO_ACCOUNT_SID=your_account_sid
TWILIO_AUTH_TOKEN=your_auth_token
TWILIO_PHONE_NUMBER=your_twilio_phone_number
SMS_TO_PHONE=your_mobile_number
```

When these variables are set, each new service request will send a notification to the webhook endpoint and an SMS to the configured phone number.


