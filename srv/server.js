"use strict";
/**
 * Mashup debugger backend.
 *
 * The app router authenticates the user and forwards the user's XSUAA JWT
 * (forwardAuthToken: true) in the Authorization header. That token never
 * reaches the browser - this service makes it visible and uses it for the
 * user token exchange at the destination service (X-user-token), which is
 * what produces the SAML assertion for "SAMLAssertion" destinations.
 */
const express = require("express");
const { createSecurityContext, XsuaaService } = require("@sap/xssec");

// ------------------------------------------------------------ service bindings
const vcap = JSON.parse(process.env.VCAP_SERVICES || "{}");
function credentials(label) {
  const svc = (vcap[label] || [])[0];
  if (!svc) throw new Error(`No '${label}' service instance bound`);
  return svc.credentials;
}
const xsuaaCreds = credentials("xsuaa");
const destCreds = credentials("destination");
const authService = new XsuaaService(xsuaaCreds);
const REQUIRED_SCOPE = "Debugger";

class HttpError extends Error {
  constructor(status, message, details) {
    super(message);
    this.status = status;
    this.details = details;
  }
}

// ------------------------------------------------------------ helpers
function b64urlJson(part) {
  return JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
}

function decodeJwt(jwt) {
  const [h, p] = jwt.split(".");
  return { header: b64urlJson(h), payload: b64urlJson(p) };
}

function isJwt(value) {
  return typeof value === "string" && /^[\w-]+\.[\w-]+\.[\w-]*$/.test(value);
}

const SECRET_KEY = /(password|secret|clientkey|keystorepassword|token)$/i;
function maskConfig(cfg = {}) {
  return Object.fromEntries(
    Object.entries(cfg).map(([k, v]) => [k, SECRET_KEY.test(k) ? "***" : v])
  );
}

/** Adds decoded views of an authToken returned by the destination service. */
function describeAuthToken(t) {
  if (!t) return null;
  const out = { ...t };
  if (/saml/i.test(t.type || "") && t.value) {
    try {
      const xml = Buffer.from(t.value, "base64").toString("utf8");
      if (xml.trim().startsWith("<")) out.decodedAssertion = xml;
    } catch { /* not base64 */ }
  } else if (isJwt(t.value)) {
    out.decodedJwt = decodeJwt(t.value);
  }
  return out;
}

function joinUrl(base, path) {
  if (!path) return base;
  return base.replace(/\/+$/, "") + "/" + path.replace(/^\/+/, "");
}

// ------------------------------------------------------------ destination service
let ccToken = { value: null, exp: 0 };

async function destinationServiceToken() {
  if (ccToken.value && Date.now() < ccToken.exp - 60_000) return ccToken.value;
  if (!destCreds.clientsecret) {
    throw new HttpError(500, "Destination binding has no clientsecret (X.509 bindings are not supported by this debugger)");
  }
  const res = await fetch(`${destCreds.url}/oauth/token`, {
    method: "POST",
    headers: {
      Authorization: "Basic " + Buffer.from(`${destCreds.clientid}:${destCreds.clientsecret}`).toString("base64"),
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({ grant_type: "client_credentials", client_id: destCreds.clientid }),
  });
  if (!res.ok) throw new HttpError(502, `Destination service token request failed: ${res.status}`, await res.text());
  const json = await res.json();
  ccToken = { value: json.access_token, exp: Date.now() + json.expires_in * 1000 };
  return ccToken.value;
}

async function destinationApi(path, userJwt) {
  const headers = { Authorization: `Bearer ${await destinationServiceToken()}` };
  if (userJwt) headers["X-user-token"] = userJwt;
  const res = await fetch(`${destCreds.uri}/destination-configuration/v1${path}`, { headers });
  const text = await res.text();
  if (!res.ok) {
    throw new HttpError(res.status === 404 ? 404 : 502, `Destination service ${path}: ${res.status}`, text);
  }
  return JSON.parse(text);
}

/** "Find destination" incl. user token exchange -> authTokens (e.g. SAML assertion). */
function findDestination(name, userJwt) {
  return destinationApi(`/destinations/${encodeURIComponent(name)}`, userJwt);
}

// ------------------------------------------------------------ app
const app = express();
app.use(express.json({ limit: "5mb" }));

app.get("/health", (_req, res) => res.json({ status: "UP" }));

// Authentication: validate the JWT forwarded by the app router
app.use("/api", async (req, res, next) => {
  try {
    req.securityContext = await createSecurityContext(authService, { req });
  } catch (e) {
    return res.status(401).json({ error: "Unauthorized", details: e.message });
  }
  if (!req.securityContext.checkLocalScope(REQUIRED_SCOPE)) {
    return res.status(403).json({ error: `Missing scope '${REQUIRED_SCOPE}' - assign role collection MashupDebugger` });
  }
  req.userJwt = req.headers.authorization.split(" ")[1];
  next();
});

const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res)).catch(next);

/** The user JWT the app router forwarded - i.e. the token used for the token exchange. */
app.get("/api/token", (req, res) => {
  const { header, payload } = decodeJwt(req.userJwt);
  const now = Math.floor(Date.now() / 1000);
  res.json({
    jwt: req.userJwt,
    header,
    payload,
    issuedAt: payload.iat ? new Date(payload.iat * 1000).toISOString() : null,
    expiresAt: payload.exp ? new Date(payload.exp * 1000).toISOString() : null,
    expiresInSeconds: payload.exp ? payload.exp - now : null,
  });
});

/** Request headers as they arrive at the backend (after the app router). */
app.get("/api/echo", (req, res) => {
  res.json({ method: req.method, url: req.originalUrl, headers: req.headers });
});

/** Subaccount + instance level destinations (secrets masked). */
app.get("/api/destinations", wrap(async (_req, res) => {
  const [sub, inst] = await Promise.all([
    destinationApi("/subaccountDestinations"),
    destinationApi("/instanceDestinations").catch(() => []),
  ]);
  const pick = (level) => (d) => ({
    level,
    name: d.Name,
    type: d.Type,
    url: d.URL,
    authentication: d.Authentication,
    proxyType: d.ProxyType,
  });
  res.json([...sub.map(pick("subaccount")), ...inst.map(pick("instance"))]);
}));

/** Find destination with user token exchange; shows the generated auth tokens / SAML assertion. */
app.get("/api/destinations/:name", wrap(async (req, res) => {
  const found = await findDestination(req.params.name, req.userJwt);
  res.json({
    owner: found.owner,
    destinationConfiguration: maskConfig(found.destinationConfiguration),
    authTokens: (found.authTokens || []).map(describeAuthToken),
    certificates: (found.certificates || []).map((c) => ({ Name: c.Name, Type: c.Type })),
  });
}));

/** Call a backend through a destination, using the exchanged token. */
app.post("/api/call", wrap(async (req, res) => {
  const { destination, method = "GET", path = "", headers = {}, body, fetchCsrf = false } = req.body || {};
  if (!destination) throw new HttpError(400, "'destination' is required");

  const found = await findDestination(destination, req.userJwt);
  const cfg = found.destinationConfiguration;
  if ((cfg.ProxyType || "Internet") !== "Internet") {
    throw new HttpError(400, `ProxyType '${cfg.ProxyType}' is not supported (Internet only)`);
  }
  const auth = (found.authTokens || [])[0];
  if (auth?.error) throw new HttpError(502, "Destination service could not create an auth token", auth.error);

  // Assemble outgoing request: destination properties, auth header, then user headers
  const url = new URL(joinUrl(cfg.URL, path));
  const outHeaders = {};
  for (const [k, v] of Object.entries(cfg)) {
    if (k.startsWith("URL.headers.")) outHeaders[k.slice(12)] = v;
    if (k.startsWith("URL.queries.")) url.searchParams.set(k.slice(12), v);
  }
  if (auth?.http_header) outHeaders[auth.http_header.key] = auth.http_header.value;
  Object.assign(outHeaders, headers);

  const steps = [];
  const upperMethod = method.toUpperCase();

  if (fetchCsrf && !["GET", "HEAD"].includes(upperMethod)) {
    const r = await fetch(url, { method: "HEAD", headers: { ...outHeaders, "X-CSRF-Token": "Fetch" } });
    const token = r.headers.get("x-csrf-token");
    const cookies = r.headers.getSetCookie().map((c) => c.split(";")[0]).join("; ");
    steps.push({ step: "csrf-fetch", status: r.status, csrfToken: token ? "(received)" : "(none)" });
    if (token) outHeaders["X-CSRF-Token"] = token;
    if (cookies) outHeaders.Cookie = cookies;
  }

  const started = Date.now();
  const r = await fetch(url, {
    method: upperMethod,
    headers: outHeaders,
    body: ["GET", "HEAD"].includes(upperMethod) || body == null || body === ""
      ? undefined
      : typeof body === "string" ? body : JSON.stringify(body),
    redirect: "manual",
  });
  const responseBody = await r.text();

  res.json({
    durationMs: Date.now() - started,
    steps,
    request: { method: upperMethod, url: url.toString(), headers: outHeaders },
    authToken: describeAuthToken(auth),
    response: {
      status: r.status,
      statusText: r.statusText,
      headers: Object.fromEntries(r.headers),
      body: responseBody,
    },
  });
}));

// ------------------------------------------------------------ errors
app.use((err, _req, res, _next) => {
  const status = err.status || 500;
  if (status >= 500) console.error(err);
  res.status(status).json({ error: err.message, details: err.details });
});

const port = process.env.PORT || 4004;
app.listen(port, () => console.log(`mashup-debugger-srv listening on ${port}`));
