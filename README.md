# Yard-services

## Render setup

This app stores the SQLite database locally in `yard.db` and saves uploaded service images, popup media, and background files to `static/uploads/`.

Add these environment variables in Render:

```bash
SECRET_KEY=your-long-random-secret
DB_LOCAL_PATH=yard.db
```

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


