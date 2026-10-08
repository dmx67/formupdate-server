import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DB_PATH = path.join(__dirname, "store.json");
const PORT = process.env.PORT || 8787;

/* ───────── Signing key (server identity) ───────── */

let SIGNING = loadSigningKey();

function loadSigningKey() {
  const keyPath = path.join(__dirname, "signing.json");
  if (fs.existsSync(keyPath)) {
    const j = JSON.parse(fs.readFileSync(keyPath, "utf8"));
    return {
      privateKey: crypto.createPrivateKey(j.privatePem),
      publicKey: crypto.createPublicKey(j.publicPem),
      publicRawB64: j.publicRawB64
    };
  }
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", {
    namedCurve: "prime256v1"
  });
  const der = publicKey.export({ type: "spki", format: "der" });
  const raw = der.subarray(der.length - 65);
  const publicRawB64 = raw.toString("base64");
  const j = {
    privatePem: privateKey.export({ type: "pkcs8", format: "pem" }),
    publicPem: publicKey.export({ type: "spki", format: "pem" }),
    publicRawB64
  };
  fs.writeFileSync(keyPath, JSON.stringify(j, null, 2));
  return {
    privateKey: crypto.createPrivateKey(j.privatePem),
    publicKey: crypto.createPublicKey(j.publicPem),
    publicRawB64
  };
}

function signString(str) {
  return crypto.sign("sha256", Buffer.from(str, "utf8"), {
    key: SIGNING.privateKey,
    dsaEncoding: "der"
  }).toString("base64");
}

/* ───────── ECDH + HKDF + AES-GCM ───────── */

function rawEcToNodeKey(rawB64) {
  const raw = Buffer.from(rawB64, "base64");
  if (raw.length !== 65 || raw[0] !== 0x04) throw new Error("bad_client_pubkey");
  const derPrefix = Buffer.from(
    "3059301306072a8648ce3d020106082a8648ce3d030107034200",
    "hex"
  );
  const der = Buffer.concat([derPrefix, raw]);
  const pem = "-----BEGIN PUBLIC KEY-----\n" +
              der.toString("base64").match(/.{1,64}/g).join("\n") +
              "\n-----END PUBLIC KEY-----\n";
  return crypto.createPublicKey(pem);
}

function ecdhSharedSecret(clientPubRawB64) {
  const clientKey = rawEcToNodeKey(clientPubRawB64);
  const { privateKey: serverEph } = crypto.generateKeyPairSync("ec", {
    namedCurve: "prime256v1"
  });
  const shared = crypto.diffieHellman({
    privateKey: serverEph,
    publicKey: clientKey
  });
  const serverPubRaw = crypto.createPublicKey(serverEph).export({ type: "spki", format: "der" }).subarray(-65);
  return { shared, serverPubRaw };
}

const HKDF_INFO = Buffer.from("guru-service-v2", "utf8");
const HKDF_SALT = Buffer.alloc(32, 0);

function hkdfAesKey(ikm) {
  const prk = crypto.createHmac("sha256", HKDF_SALT).update(ikm).digest();
  const okm = crypto.createHmac("sha256", prk)
    .update(Buffer.concat([HKDF_INFO, Buffer.from([1])])).digest();
  return okm.subarray(0, 32);
}

function aesGcmDecrypt(key, ivB64, ctB64, tagB64) {
  const iv = Buffer.from(ivB64, "base64");
  const ct = Buffer.from(ctB64, "base64");
  const tag = Buffer.from(tagB64, "base64");
  const d = crypto.createDecipheriv("aes-256-gcm", key, iv);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]).toString("utf8");
}

function aesGcmEncrypt(key, iv, plaintextStr) {
  const c = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([c.update(Buffer.from(plaintextStr, "utf8")), c.final()]);
  return { ct, tag: c.getAuthTag() };
}

/* ───────── Persistent store ───────── */

let DB = fs.existsSync(DB_PATH)
  ? JSON.parse(fs.readFileSync(DB_PATH, "utf8"))
  : { sessions: {}, leases: {}, history: {}, users: {} };

if (!DB.users) DB.users = {};
if (!DB.sessions) DB.sessions = {};
if (!DB.leases) DB.leases = {};
if (!DB.history) DB.history = {};

function save() {
  fs.writeFileSync(DB_PATH, JSON.stringify(DB, null, 2));
}

/* ───────── Envelope helpers ───────── */

function openEnvelope(envelope) {
  if (!envelope || envelope.version !== 2) throw new Error("bad_envelope_version");
  const { shared, serverPubRaw } = ecdhSharedSecret(envelope.client_ephemeral_public_key);
  const aesKey = hkdfAesKey(shared);
  const plaintext = aesGcmDecrypt(
    aesKey,
    envelope.nonce,
    envelope.ciphertext,
    envelope.authentication_tag
  );
  return {
    body: JSON.parse(plaintext),
    aesKey,
    serverPubRawB64: serverPubRaw.toString("base64")
  };
}

function sealResponse(aesKey, serverPubRawB64, requestId, plaintextObj) {
  const iv = crypto.randomBytes(12);
  const { ct, tag } = aesGcmEncrypt(aesKey, iv, JSON.stringify(plaintextObj));
  const envelope = {
    version: 2,
    request_id: requestId,
    server_ephemeral_public_key: serverPubRawB64,
    nonce: iv.toString("base64"),
    ciphertext: ct.toString("base64"),
    authentication_tag: tag.toString("base64"),
    algorithm: "ECDH-P256-HKDF-SHA256-AES-256-GCM"
  };
  const canonical = [
    envelope.version,
    envelope.request_id,
    envelope.algorithm,
    envelope.server_ephemeral_public_key,
    envelope.nonce,
    envelope.ciphertext,
    envelope.authentication_tag
  ].join(":");
  envelope.server_signature = signString(canonical);
  return envelope;
}

/* ───────── Sessions + user accounts ───────── */

const STARTER_TOKENS = 50000;
const COST_PER_CHARGE = 1500;
const BLOCKS_PER_CHARGE = 4;

const newExtensionId = () => "ext_" + crypto.randomBytes(12).toString("hex");
const newLeaseId = () => "ls_" + crypto.randomBytes(12).toString("hex");

function getOrCreateSession(extensionId, fingerprint) {
  if (extensionId && DB.sessions[extensionId]) return DB.sessions[extensionId];
  const id = extensionId || newExtensionId();
  const s = {
    extensionId: id,
    fingerprint: fingerprint || "unknown",
    tokens: STARTER_TOKENS,
    block_remainder: 0,
    blocks_per_charge: BLOCKS_PER_CHARGE,
    banned: false,
    createdAt: Date.now(),
    lastSeen: Date.now()
  };
  DB.sessions[id] = s;
  DB.history[id] = DB.history[id] || [];
  save();
  return s;
}

/* ───────── Express ───────── */

const app = express();
app.use(cors({ origin: true, credentials: true }));
app.use(cookieParser());
app.use(express.json({ limit: "1mb" }));

app.get("/g/xk", (_req, res) => {
  res.json({
    status: "ok",
    pubkey: SIGNING.publicRawB64,
    signature: signString(SIGNING.publicRawB64)
  });
});

/* ───────── /g/xa  →  login / register ───────── */
app.post("/g/xa", handle(openEnvelope, async (body) => {
  const { username, password } = body;

  // No credentials → anonymous session (backward compatible)
  if (!username || !password) {
    const s = getOrCreateSession(null, body.fingerprint);
    const leaseId = newLeaseId();
    DB.leases[leaseId] = { extensionId: s.extensionId, expiresAt: Date.now() + 3600000 };
    save();
    return {
      status: "authenticated",
      extension_id: s.extensionId,
      lease_id: leaseId,
      tokens: s.tokens,
      block_remainder: s.block_remainder,
      blocks_per_charge: s.blocks_per_charge,
      contact: { whatsapp: "+10000000000", telegram: "@formupdate_support" }
    };
  }

  // With credentials → register if new, else log in
  let user = DB.users[username];

  if (!user) {
    // Register new user
    user = {
      username,
      passwordHash: crypto.createHash("sha256").update(password).digest("hex"),
      extensionId: newExtensionId(),
      tokens: STARTER_TOKENS,
      block_remainder: 0,
      blocks_per_charge: BLOCKS_PER_CHARGE,
      banned: false,
      createdAt: Date.now(),
      lastSeen: Date.now()
    };
    DB.users[username] = user;
    DB.sessions[user.extensionId] = {
      extensionId: user.extensionId,
      fingerprint: "user:" + username,
      tokens: user.tokens,
      block_remainder: user.block_remainder,
      blocks_per_charge: user.blocks_per_charge,
      banned: false,
      createdAt: user.createdAt,
      lastSeen: user.lastSeen
    };
    DB.history[user.extensionId] = DB.history[user.extensionId] || [];
    save();
  } else {
    // Login existing user
    const passwordHash = crypto.createHash("sha256").update(password).digest("hex");
    if (passwordHash !== user.passwordHash) {
      throw httpError(401, "UNAUTHORIZED");
    }
    if (user.banned) throw httpError(403, "ACCOUNT_BANNED");

    // Refresh the session for this user
    DB.sessions[user.extensionId] = {
      extensionId: user.extensionId,
      fingerprint: "user:" + username,
      tokens: user.tokens,
      block_remainder: user.block_remainder,
      blocks_per_charge: user.blocks_per_charge,
      banned: user.banned,
      createdAt: user.createdAt,
      lastSeen: Date.now()
    };
    save();
  }

  const s = DB.sessions[user.extensionId];
  const leaseId = newLeaseId();
  DB.leases[leaseId] = { extensionId: user.extensionId, expiresAt: Date.now() + 3600000 };
  save();

  return {
    status: "authenticated",
    extension_id: user.extensionId,
    lease_id: leaseId,
    tokens: s.tokens,
    block_remainder: s.block_remainder,
    blocks_per_charge: s.blocks_per_charge,
    contact: { whatsapp: "+10000000000", telegram: "@formupdate_support" }
  };
}));

app.post("/g/xm", handle(openEnvelope, async (_body, session) => {
  const eid = session?.extensionId;
  if (!eid) throw httpError(401, "UNAUTHORIZED");
  const s = DB.sessions[eid];
  if (!s) throw httpError(401, "UNAUTHORIZED");
  if (s.banned) throw httpError(403, "ACCOUNT_BANNED");

  const leaseId = newLeaseId();
  DB.leases[leaseId] = { extensionId: eid, expiresAt: Date.now() + 3600000 };
  s.lastSeen = Date.now();
  save();

  return {
    status: "authorized",
    lease_id: leaseId,
    expires_at: Date.now() + 3600000,
    configuration_version: "2.1.0",
    contact: { whatsapp: "+10000000000", telegram: "@formupdate_support" },
    rules: []
  };
}));

app.post("/g/xp", handle(openEnvelope, async (body, session) => {
  const eid = session?.extensionId;
  if (!eid) throw httpError(401, "UNAUTHORIZED");
  const s = DB.sessions[eid];
  if (!s) throw httpError(401, "UNAUTHORIZED");
  if (s.banned) return { status: "denied", reason: "ACCOUNT_BANNED" };

  s.lastSeen = Date.now();

  const ledger = Array.isArray(body.pending_ledger) ? body.pending_ledger : [];
  for (const tx of ledger) {
    if (typeof tx.charge === "number" && tx.charge > 0) {
      s.tokens = Math.max(0, s.tokens - tx.charge);
      DB.history[eid].push({
        tx_id: tx.tx_id || crypto.randomUUID(),
        type: "charge_pending",
        amount: -tx.charge,
        created_at: new Date(tx.timestamp || Date.now()).toISOString()
      });
    }
  }

  // Sync user record
  const user = Object.values(DB.users).find(u => u.extensionId === eid);
  if (user) {
    user.tokens = s.tokens;
    user.block_remainder = s.block_remainder;
    user.lastSeen = Date.now();
  }
  save();

  return {
    _v6r: "_ok",
    _q7z: s.tokens,
    _x2m: s.block_remainder,
    _w9s: s.blocks_per_charge,
    _t5f: false
  };
}));

app.post("/g/xe", handle(openEnvelope, async (body, session) => {
  const eid = session?.extensionId;
  if (!eid) throw httpError(401, "UNAUTHORIZED");
  const s = DB.sessions[eid];
  if (!s) throw httpError(401, "UNAUTHORIZED");
  if (s.banned) return { status: "denied", reason: "ACCOUNT_BANNED" };

  const blocks = Number(body.blocks) || 1;
  let rem = s.block_remainder + blocks;
  if (rem >= s.blocks_per_charge) {
    const charges = Math.floor(rem / s.blocks_per_charge);
    rem = rem % s.blocks_per_charge;
    const cost = charges * COST_PER_CHARGE;
    if (s.tokens < cost) {
      return {
        status: "denied",
        reason: "INSUFFICIENT_BALANCE",
        tokens: s.tokens,
        block_remainder: rem,
        blocks_per_charge: s.blocks_per_charge
      };
    }
    s.tokens -= cost;
    DB.history[eid].push({
      tx_id: crypto.randomUUID(),
      type: "usage",
      amount: -cost,
      rule_id: body.ruleId,
      created_at: new Date().toISOString()
    });
  }
  s.block_remainder = rem;
  s.lastSeen = Date.now();
  save();

  return {
    status: "accepted",
    tokens: s.tokens,
    block_remainder: s.block_remainder,
    blocks_per_charge: s.blocks_per_charge
  };
}));

app.post("/g/xh", handle(openEnvelope, async (_body, session) => {
  const eid = session?.extensionId;
  if (!eid) throw httpError(401, "UNAUTHORIZED");
  const s = DB.sessions[eid];
  if (!s) throw httpError(401, "UNAUTHORIZED");

  const history = (DB.history[eid] || []).slice(-50).reverse();
  const totalBought = history.filter(h => h.amount > 0).reduce((a, b) => a + b.amount, 0);

  return {
    status: "ok",
    tokens: s.tokens,
    block_remainder: s.block_remainder,
    blocks_per_charge: s.blocks_per_charge,
    total_bought: totalBought,
    total_spent: 0,
    transactions: history
  };
}));

app.post("/g/xc", handle(openEnvelope, async () => ({
  status: "ok",
  whatsapp: "+10000000000",
  telegram: "@formupdate_support"
})));

/* ───────── Handler wrapper ───────── */

function httpError(status, reason) {
  const e = new Error(reason);
  e.status = status;
  return e;
}

function handle(opener, fn) {
  return async (req, res) => {
    try {
      const envelope = req.body;
      if (!envelope || typeof envelope !== "object") {
        return res.status(400).json({ error: "bad_request" });
      }
      const { body, aesKey, serverPubRawB64 } = opener(envelope);
      const eid = req.header("X-EID") || body.extensionId || null;
      const session = eid && DB.sessions[eid] ? DB.sessions[eid] : null;
      const out = await fn(body, session);
      res.json(sealResponse(aesKey, serverPubRawB64, envelope.request_id, out));
    } catch (err) {
      console.error("SERVER ERROR:", err.message);
      res.status(err.status || 500).json({
        error: err.message || "server_error",
        reason: err.message || "server_error"
      });
    }
  };
}

app.listen(PORT, () => {
  console.log(`formUpdate server listening on http://localhost:${PORT}`);
  console.log(`Server public key (raw b64): ${SIGNING.publicRawB64}`);
});