# Northstar Access Control API

Express and MongoDB API for the Northstar access-control assignment demo.

## Run locally

From this repository root, run `npm install` and `npm start`. Configure the environment using `.env.example`. For local in-memory development, run `npm run dev`.

## Deploy

Set `NODE_ENV=production`, `MONGODB_URI`, `JWT_SECRET`, `ADMIN_BOOTSTRAP_TOKEN`, and `APP_ORIGINS`. Use a replica-set-enabled MongoDB URI for transactions. Set `APP_ORIGINS` to the exact HTTPS frontend origin. Configure `RESEND_API_KEY` and `PASSWORD_RESET_FROM_EMAIL` only if password-reset emails are needed; without them, the API starts normally and password recovery is unavailable. The frontend and API should use HTTPS and preferably custom domains under the same site so browser session cookies work reliably.
