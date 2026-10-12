# Yard Services — Project Roadmap

This roadmap lists possible improvements for the Yard Services project. These are ideas for future work, not claims that the features are already implemented.

## User experience
- [ ] Make the service-request form easier to use on phones.
- [ ] Show clear success, validation, and error messages after form submissions.
- [ ] Add service categories, service-area details, and an FAQ section.
- [ ] Improve empty states so visitors know what to do when no services or requests are listed.

## Request management
- [ ] Add request statuses such as New, In Progress, Completed, and Cancelled.
- [ ] Add search and filters for administrators.
- [ ] Validate uploaded images by file type and size, and use safe generated filenames.
- [ ] Add pagination if request lists become large.

## Reliability and security
- [ ] Keep secrets in environment variables and never commit real credentials.
- [ ] Add automated tests for request validation and database operations.
- [ ] Document database backups and restore steps.
- [ ] Review authentication, upload handling, and webhook configuration before deployment.

## Deployment checklist
- [ ] Confirm production uses a persistent database/storage configuration.
- [ ] Set a strong, unique `SECRET_KEY`.
- [ ] Test the app with missing or invalid environment variables.
- [ ] Verify that private customer information is not exposed in logs or public pages.
