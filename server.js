import "dotenv/config";
import express from "express";
import session from "express-session";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json());

app.use(session({
  secret: process.env.SESSION_SECRET || "dev-only-secret",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 1000 * 60 * 60 * 24 * 7,
  },
}));

app.use(express.static(path.join(__dirname, "public")));

const rpName = process.env.RP_NAME || "Passkey Demo";
const rpID = process.env.RP_ID || "localhost";
const origin = process.env.ORIGIN || "http://localhost:3000";

/* TEST ONLY: all data disappears when Node restarts. */
const users = new Map();
const passkeys = new Map();

function newId(prefix) {
  return `${prefix}_${crypto.randomUUID()}`;
}

function getUserById(id) {
  return [...users.values()].find((u) => u.id === id);
}

function getUserPasskeys(userId) {
  return [...passkeys.values()].filter((p) => p.userId === userId);
}

function requireUser(req, res) {
  const user = getUserById(req.session.userId);
  if (!user) {
    res.status(401).json({ error: "Not authenticated" });
    return null;
  }
  return user;
}

/* Signup */
app.post("/api/users", async (req, res) => {
  try {
    const username = String(req.body.username || "").trim().toLowerCase();
    const displayName = String(req.body.displayName || "").trim();

    if (!/^[a-z0-9._-]{3,32}$/.test(username)) {
      return res.status(400).json({
        error: "Username must be 3-32 characters: letters, numbers, dot, underscore or hyphen.",
      });
    }

    if (!displayName) {
      return res.status(400).json({ error: "Display name is required." });
    }

    if (users.has(username)) {
      return res.status(409).json({ error: "That username is already taken." });
    }

    const user = {
      id: newId("user"),
      username,
      displayName,
      webauthnUserID: crypto.randomUUID(),
      createdAt: new Date().toISOString(),
    };

    users.set(username, user);
    req.session.userId = user.id;

    res.json({
      id: user.id,
      username: user.username,
      displayName: user.displayName,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Could not create account." });
  }
});

/* Passkey registration options */
app.get("/api/passkey/register/options", async (req, res) => {
  try {
    const user = requireUser(req, res);
    if (!user) return;

    const existing = getUserPasskeys(user.id);

    const options = await generateRegistrationOptions({
      rpName,
      rpID,
      userName: user.username,
      userDisplayName: user.displayName,
      userID: new TextEncoder().encode(user.webauthnUserID),
      attestationType: "none",
      excludeCredentials: existing.map((p) => ({
        id: p.id,
        transports: p.transports,
      })),
      authenticatorSelection: {
        residentKey: "required",
        userVerification: "preferred",
      },
    });

    req.session.registrationChallenge = options.challenge;
    req.session.registrationUserId = user.id;

    res.json(options);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Could not start passkey registration." });
  }
});

/* Passkey registration verification */
app.post("/api/passkey/register/verify", async (req, res) => {
  try {
    const userId = req.session.registrationUserId;
    const expectedChallenge = req.session.registrationChallenge;

    if (!userId || !expectedChallenge) {
      return res.status(400).json({ error: "Registration session expired. Try again." });
    }

    const user = getUserById(userId);
    if (!user) return res.status(401).json({ error: "User not found." });

    let verification;
    try {
      verification = await verifyRegistrationResponse({
        response: req.body,
        expectedChallenge,
        expectedOrigin: origin,
        expectedRPID: rpID,
      });
    } catch (error) {
      console.error("Registration verification:", error);
      return res.status(400).json({ error: "The passkey could not be verified." });
    }

    if (!verification.verified || !verification.registrationInfo) {
      return res.status(400).json({ error: "Passkey registration failed." });
    }

    const {
      credential,
      credentialDeviceType,
      credentialBackedUp,
    } = verification.registrationInfo;

    passkeys.set(credential.id, {
      id: credential.id,
      userId: user.id,
      webauthnUserID: user.webauthnUserID,
      publicKey: credential.publicKey,
      counter: credential.counter,
      deviceType: credentialDeviceType,
      backedUp: credentialBackedUp,
      transports: credential.transports ?? [],
      createdAt: new Date().toISOString(),
    });

    delete req.session.registrationChallenge;
    delete req.session.registrationUserId;

    res.json({ verified: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Could not register passkey." });
  }
});

/* Login options */
app.post("/api/passkey/login/options", async (req, res) => {
  try {
    const username = String(req.body.username || "").trim().toLowerCase();
    const user = users.get(username);

    if (!user) return res.status(404).json({ error: "Account not found." });

    const userPasskeys = getUserPasskeys(user.id);
    if (!userPasskeys.length) {
      return res.status(400).json({ error: "No passkey is registered for this account." });
    }

    const options = await generateAuthenticationOptions({
      rpID,
      allowCredentials: userPasskeys.map((p) => ({
        id: p.id,
        transports: p.transports,
      })),
      userVerification: "preferred",
    });

    req.session.authenticationChallenge = options.challenge;
    req.session.authenticationUserId = user.id;

    res.json(options);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Could not start passkey login." });
  }
});

/* Login verification */
app.post("/api/passkey/login/verify", async (req, res) => {
  try {
    const userId = req.session.authenticationUserId;
    const expectedChallenge = req.session.authenticationChallenge;

    if (!userId || !expectedChallenge) {
      return res.status(400).json({ error: "Login session expired. Try again." });
    }

    const user = getUserById(userId);
    if (!user) return res.status(401).json({ error: "Account not found." });

    const passkey = passkeys.get(req.body.id);
    if (!passkey || passkey.userId !== user.id) {
      return res.status(401).json({ error: "Passkey not found for this account." });
    }

    let verification;
    try {
      verification = await verifyAuthenticationResponse({
        response: req.body,
        expectedChallenge,
        expectedOrigin: origin,
        expectedRPID: rpID,
        credential: {
          id: passkey.id,
          publicKey: new Uint8Array(passkey.publicKey),
          counter: passkey.counter,
          transports: passkey.transports,
        },
      });
    } catch (error) {
      console.error("Authentication verification:", error);
      return res.status(401).json({ error: "Passkey authentication failed." });
    }

    if (!verification.verified) {
      return res.status(401).json({ error: "Passkey authentication failed." });
    }

    passkey.counter = verification.authenticationInfo.newCounter;
    req.session.userId = user.id;

    delete req.session.authenticationChallenge;
    delete req.session.authenticationUserId;

    res.json({
      verified: true,
      user: {
        id: user.id,
        username: user.username,
        displayName: user.displayName,
      },
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Could not authenticate." });
  }
});

app.get("/api/me", (req, res) => {
  const user = getUserById(req.session.userId);
  if (!user) return res.json({ authenticated: false });

  res.json({
    authenticated: true,
    user: {
      id: user.id,
      username: user.username,
      displayName: user.displayName,
    },
  });
});

app.get("/api/stats", (req, res) => {
  const user = getUserById(req.session.userId);
  if (!user) return res.status(401).json({ error: "Not authenticated" });

  res.json({
    passkeys: getUserPasskeys(user.id).length,
    usersInMemory: users.size,
  });
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

app.get("/api/debug", (req, res) => {
  res.json({ users: users.size, passkeys: passkeys.size });
});

app.listen(Number(process.env.PORT) || 3000, () => {
  console.log(`Passkey demo running at ${origin}`);
  console.log(`RP ID: ${rpID}`);
});
