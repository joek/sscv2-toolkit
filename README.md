# Mashup Debugger for SAP Sales and Service Cloud V2

A BTP Cloud Foundry app (app router + Node.js backend) that you can embed as a mashup in SSCV2 to debug:

| Tab | What it does |
|---|---|
| **UI Events** | Logs every `window.postMessage` the host sends, shows the mashup context (iframe, referrer, URL parameters) and can post messages to the host. |
| **JWT Token** | Shows the **user JWT the app router forwards to the backend** (raw + decoded, expiry countdown, copy). This token never reaches the browser otherwise; it is the one sent as `X-user-token` to the destination service for the token exchange. Also shows all request headers as the backend receives them. |
| **Destinations** | Lists subaccount/instance destinations and runs a *find destination* **with user token exchange**, showing the generated auth tokens. For `SAMLAssertion` destinations the SAML assertion is base64-decoded and shown as XML (subject, attributes, audience, validity). |
| **Backend Call** | Calls any path on a destination, using the exchanged token. Applies `URL.headers.*` / `URL.queries.*` destination properties, can fetch a CSRF token first, and replaces `{{param}}` in the path with mashup URL parameters (e.g. `{{accountId}}`). |

## How it works

```
SSCV2 (iframe) ──► App Router ──(user JWT, forwardAuthToken)──► srv ──► Destination service
                   (XSUAA login)                                 │      find destination + X-user-token
                                                                 │      ◄── authTokens (SAML2.0 assertion)
                                                                 └────► SSCV2 / backend API
                                                                        Authorization: SAML2.0 …
```

## Layout

```
mta.yaml              MTA descriptor (xsuaa, destination, srv, approuter)
xs-security.json      Scope "Debugger", role collection "MashupDebugger"
approuter/            @sap/approuter, xs-app.json, resources/index.html (the UI)
srv/                  Express backend: /api/token, /api/echo, /api/destinations[/:name], /api/call
```

## Deploy

```sh
cf login ...
mbt build
cf deploy mta_archives/mashup-app-debugger_1.0.0.mtar
```

Then in the BTP cockpit:

1. **Role collection**: assign `MashupDebugger` to your user (otherwise the API returns 403).
2. **Destination**: create a destination with `Authentication: SAMLAssertion`, `ProxyType: Internet`, the SSCV2 tenant URL, and the audience / name ID settings that the SSCV2 trust setup expects.
3. **SSCV2**: create a URL mashup pointing at the app router URL. Use URL parameters to pass context (e.g. account ID) and reference them in the path as `{{name}}`.

## Embedding notes

- **Framing**: the app router sends `Content-Security-Policy: frame-ancestors 'self' https://*.crm.cloud.sap`. Change the `frame-ancestors` parameter in `mta.yaml` if your tenant has a different host.
- **Cookies**: `COOKIES: {"SameSite":"None"}` is set so the app router session cookie works inside the iframe. Browsers that block third-party cookies by default can still break the session; if so, allow cookies for the app router host.
- **Login in iframe**: XSUAA/IAS login pages usually refuse to be framed. Use the same IAS tenant for SSCV2 and the BTP subaccount so SSO happens silently, or open the app once in a separate tab to establish the session.

## Security

The token endpoint returns the caller's **own** JWT, and `/api/call` acts as a proxy to any configured destination. Both require the `Debugger` scope. Only assign the role collection to developers, and don't deploy this app to productive subaccounts.

## Limitations

- Only `ProxyType: Internet` (no Cloud Connector / on-premise).
- The destination service binding must use client secret credentials (no X.509 binding).
- The first `authTokens` entry of a destination is used.
