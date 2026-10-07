# Enterprise Multi-Tenant Security Gateway

CSC337 - Advanced Web Technologies - Lab Assignment 05

Node.js + Express + MongoDB gateway with hybrid authentication (local Bcrypt + Google/GitHub OAuth 2.0), access/refresh token rotation, role-based access control and OWASP hardening.

**Live URL:** https://enterprise-security-gateway-a50d.onrender.com

**GitHub:**  https://github.com/zenbaayy/enterprise-security-gateway

## Test credentials

| Role       | Email                    | Password        |
|------------|--------------------------|-----------------|
| SuperAdmin | superadmin@example.com   | SuperAdmin@123  |
| Manager    | manager@example.com      | Manager@1234    |
| Employee   | employee@example.com     | Employee@123    |

These accounts are auto-created on startup (`SEED_TEST_USERS=true`).
### github connected
<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/e954a243-d7ab-4044-83b6-ee64e065c5b0" />

### manager login
<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/e60aa66b-d28d-43dc-b75d-f41c57ded857" />

### failed attempts account lock
<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/ec286814-f386-443b-b61f-59267707015e" />
### employe file

<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/f453391b-5548-4f57-b669-f73c5d93084e" />


### refresh token
<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/f2b84050-a6c6-4206-8b56-c9bbf67c7b62" />


### supeer login
<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/99c5fd53-b9f3-472c-954a-87a2dd1fc881" />





## Features mapped to the assignment

| Requirement | Implementation |
|---|---|
| Register / Login | `POST /api/v1/auth/register`, `POST /api/v1/auth/login` |
| Password hashing | Bcrypt (bcryptjs, 12 salt rounds). Plain-text passwords are never stored; hash field is `select:false` |
| Lockout / rate limiting | `express-rate-limit`: 5 failed logins / 15 min per IP, PLUS per-account lockout (5 failures = locked 15 min, HTTP 423) |
| Social login | Google + GitHub via Passport.js, state-parameter CSRF check, profile synced to local user, our own tokens issued on callback |
| Access token | JWT, 15 min, sent as `Authorization: Bearer` |
| Refresh token | JWT, 7 days, httpOnly + Secure + SameSite=Strict cookie (scoped to `/api/v1/auth`) |
| Rotation | `POST /api/v1/auth/refresh` revokes the used token and issues a new one. Re-using an old token revokes the whole session family (theft detection) |
| Revocation | `POST /api/v1/auth/logout` revokes the session and clears the cookie |
| RBAC | `checkRole([...])` middleware, roles SuperAdmin / Manager / Employee |
| OWASP | Helmet, strict CORS allow-list, express-mongo-sanitize (NoSQL injection), xss (XSS), input type validation, 10kb body limit, generic error messages, no stack traces, bcrypt timing equalisation |

### Route access matrix

| Route | Employee | Manager | SuperAdmin |
|---|---|---|---|
| `GET /api/v1/employee/profile` | yes | yes | yes |
| `POST /api/v1/payroll/approve` | 403 | yes | yes |
| `DELETE /api/v1/users/:id` | 403 | 403 | yes |
| `GET /api/v1/users` (helper to find ids) | 403 | 403 | yes |

New registrations and new social users always get the `Employee` role; the role can never be set from the request body.

## Run locally

```bash
npm install
cp .env.example .env      # then fill in MONGODB_URI and the two JWT secrets
npm start                 # http://localhost:5000
```

Generate secrets:
```bash
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
```

For Postman over plain `http://localhost`, set `COOKIE_SECURE=false` in `.env` (Postman will not send Secure cookies over http). On the deployed HTTPS site leave it as `true`.

## Deploy (Render + MongoDB Atlas, both free)

1. **MongoDB Atlas**: create a free cluster, a database user, and under Network Access allow `0.0.0.0/0`. Copy the connection string and add a database name, e.g. `.../security_gateway`.
2. **GitHub**: create a **public** repo and push this project (`.env` and `node_modules` are git-ignored).
3. **Render**: New > Web Service > connect the repo. Build command `npm install`, start command `npm start`. (Or use New > Blueprint, which reads `render.yaml`.)
4. Add environment variables in Render:
   - `NODE_ENV=production`
   - `BASE_URL=https:https://enterprise-security-gateway-a50d.onrender.com (no trailing slash)
   - `MONGODB_URI=...`
   - `JWT_ACCESS_SECRET=...` and `JWT_REFRESH_SECRET=...` (two different long random strings)
   - `SEED_TEST_USERS=true`
   - OAuth keys (next section)
5. Deploy, then open https://enterprise-security-gateway-a50d.onrender.com/health (should return `{"status":"ok"}`) and the home page.

Free Render services sleep after inactivity. Open the URL a minute before your viva.

## OAuth setup

**Google** (console.cloud.google.com > APIs & Services > Credentials > OAuth client ID > Web application)
- Authorized redirect URI: https://enterprise-security-gateway-a50d.onrender.com/api/v1`
- Also add https://enterprise-security-gateway-a50d.onrender.com for local testing
- Set `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`
- On the OAuth consent screen, add yourself as a test user if the app is in "Testing" mode

**GitHub** (Settings > Developer settings > OAuth Apps > New)
- Homepage URL: https://enterprise-security-gateway-a50d.onrender.com
- Authorization callback URL: `https://enterprise-security-gateway-a50d.onrender.com/api/v1
- Set `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET`

A provider whose keys are missing simply returns 501 and the rest of the app keeps working.

## Viva cheat-sheet (Postman or curl)

https://enterprise-security-gateway-a50d.onrender.com

**1. Login and get tokens**
```bash
curl -i -c jar.txt -X POST $URL/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"manager@example.com","password":"Manager@1234"}'
```
Shows `accessToken` in JSON and `Set-Cookie: refreshToken=...; HttpOnly; Secure; SameSite=Strict`.

**2. Refresh token rotation**
```bash
cp jar.txt old.txt
curl -i -b jar.txt -c jar.txt -X POST $URL/api/v1/auth/refresh      # 200, new cookie value
curl -i -b old.txt -X POST $URL/api/v1/auth/refresh                 # 401 reuse detected, session revoked
```
In Postman: send `/refresh` twice and watch the cookie change; paste the old cookie back to show reuse detection.

**3. Rate limiting / lockout** - send 6 wrong passwords
```bash
for i in 1 2 3 4 5 6; do
  curl -s -o /dev/null -w "%{http_code}\n" -X POST $URL/api/v1/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"employee@example.com","password":"wrong"}'
done
```
Attempts 1-5 return 401 (the 5th also locks the account), attempt 6 returns 429 from the IP rate limiter. Trying the correct password afterwards returns 423 (locked).

**4. RBAC rejection** - log in as Employee, then:
```bash
curl -i -X POST $URL/api/v1/payroll/approve \
  -H "Authorization: Bearer <EMPLOYEE_ACCESS_TOKEN>" -H "Content-Type: application/json" \
  -d '{"employeeId":"<ID>","amount":50000,"period":"2026-10"}'      # 403 Forbidden
curl -i -X DELETE $URL/api/v1/users/<ID> -H "Authorization: Bearer <EMPLOYEE_ACCESS_TOKEN>"   # 403
```
Same calls with the Manager token: payroll succeeds (201), delete is still 403. With the SuperAdmin token both succeed. Get user ids with `GET /api/v1/users` as SuperAdmin.

**5. Injection attempt** - NoSQL operators are rejected/neutralised:
```bash
curl -i -X POST $URL/api/v1/auth/login -H "Content-Type: application/json" \
  -d '{"email":{"$gt":""},"password":{"$gt":""}}'                   # 400
```

**6. OAuth** - open the home page and click "Continue with Google/GitHub". After the redirect the page shows the logged-in user, issued via our own JWT + refresh cookie.

## Project structure

```
server.js                  entry: connects MongoDB, seeds demo users, starts server
src/app.js                 Express app: Helmet, CORS, sanitisation, routes
src/config.js              environment config
src/passport.js            Google/GitHub strategies + profile sync
src/middleware/            auth (JWT + checkRole), rateLimit, sanitize
src/models/                User, RefreshToken, Payroll
src/routes/                auth, employee, payroll, users
src/utils/tokens.js        access/refresh token + cookie helpers
src/seed.js                demo accounts
public/                    small demo UI for the viva
```

## Security notes

- Access token lives only in browser memory (never localStorage); refresh token is unreadable by JavaScript.
- Refresh tokens are tracked by id in MongoDB (TTL index auto-cleans expired ones); rotation is atomic so a token can be used once.
- Login errors are generic ("Invalid email or password") and take the same time whether or not the email exists.
- OAuth accounts are only linked to an existing local account when the provider reports the email as verified.
