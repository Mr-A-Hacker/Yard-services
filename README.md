# Yard-services

## Render + Backblaze B2 setup

This app now supports Backblaze B2 persistence and file uploads in Render. Add these environment variables in Render:

```bash
SECRET_KEY=your-long-random-secret
B2_KEY_ID=your_backblaze_key_id
B2_APP_KEY=your_backblaze_application_key
B2_BUCKET=Yard-for-st
B2_BUCKET_NAME=Yard-for-st
B2_ENDPOINT=s3.us-east-005.backblazeb2.com
B2_DB_PATH=yard.db
DB_LOCAL_PATH=yard.db
```

The app also accepts the aliases BACKBLAZE_KEY_ID, BACKBLAZE_APP_KEY, and BACKBLAZE_BUCKET if you prefer those names.

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

## B2 Startup Sync

If `B2_KEY_ID`, `B2_APP_KEY`, and `B2_BUCKET` (or their aliases) are configured, the application will attempt to download the SQLite DB file from the configured B2 bucket on startup and initialize the local schema from that DB. After initialization the app loads a lightweight in-memory cache of `users`, `services`, and `requests` for quick access.

Environment variables used for B2:

```bash
# Backblaze B2 credentials and bucket
B2_KEY_ID=your_backblaze_key_id
B2_APP_KEY=your_backblaze_application_key
B2_BUCKET=your_bucket_name
# Optional: custom endpoint if using an S3-compatible endpoint
B2_ENDPOINT=s3.us-east-005.backblazeb2.com
# DB paths (defaults to yard.db)
B2_DB_PATH=yard.db
DB_LOCAL_PATH=yard.db
```

