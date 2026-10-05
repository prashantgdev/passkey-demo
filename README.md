# Passkey Demo

A small Node.js + Express + SimpleWebAuthn passkey testing project.

## Pages

- `/` — landing/home page
- `/signup.html` — signup + passkey registration
- `/login.html` — passkey login
- `/home.html` — authenticated dashboard

## Storage

There is NO database.

The app stores users and passkeys in JavaScript `Map` objects:

```js
const users = new Map();
const passkeys = new Map();
```

Restarting Node.js clears all users and passkeys.

Express sessions are also intentionally using the default in-memory store for this test project.

## Run

Requires Node.js 22+.

```bash
npm install
cp .env.example .env
npm start
```

Open:

http://localhost:3000

## Test

1. Open Create account.
2. Enter a username and display name.
3. Create the account.
4. Complete the browser passkey prompt.
5. You will be redirected to the dashboard.
6. Log out.
7. Use the Login page and authenticate with the same passkey.

## Production

This project is intentionally for testing. For production, use:

- a real database
- a persistent session store
- HTTPS
- production WebAuthn RP/origin configuration
- proper account recovery
- rate limiting and abuse protection
