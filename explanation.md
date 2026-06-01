# DarkShield Explanation

DarkShield monitors GitHub repositories for exposed secrets, stores the findings in Supabase, and surfaces cross-repo reuse so the most dangerous leaks are easy to prioritize.

## What the app does

1. A user signs in with Supabase Auth.
2. The user adds one or more GitHub repository URLs.
3. The backend scans each repository for secret patterns.
4. Findings are stored in Supabase and shown in the frontend.
5. Groq generates a short analyst summary for the scan.
6. Cross-repo clustering groups identical secrets across repositories.
7. Critical findings trigger email alerts when SMTP is configured.

## Main pages

- `/login`
  - Email and password login via Supabase Auth.
- `/`
  - List of monitored repositories.
  - Add Repo flow.
  - Scan Now actions.
- `/repos/[id]`
  - Full report for one repository.
  - AI reasoning card.
  - Exposure time and exposure score columns.
  - Cross-repo cluster warning banner.
- `/clusters`
  - Secrets found in more than one repository.

## Backend features

### Secret scanning

The backend scans raw file contents from GitHub and matches secrets with regex patterns such as:

- AWS access keys
- AWS secret keys
- OpenAI keys
- Anthropic keys
- Groq keys
- GitHub tokens
- Stripe secrets
- Google API keys
- Slack tokens
- private keys
- generic password-like assignments
- generic secret-like assignments

### Secret hashing and clustering

Every detected secret value is hashed with SHA256 or HMAC-SHA256, depending on configuration. Identical hashes are treated as the same secret across repositories.

That hash is used to:

- link findings to clusters
- count how many repos share the same secret
- prevent duplicate alert spam for the same exposure set

### Exposure time and exposure score

For each finding, the backend attempts to look up the first commit date of the file through the GitHub commits API.

- `exposure_days` = days since first commit
- `exposure_score` = severity weight multiplied by `log2(exposure_days + 2)`

If the values already exist in the database, the API returns them directly.
If older rows are missing those fields, the read path backfills them when possible.

### Groq reasoning

If `GROQ_API_KEY` is present, the backend sends the scan summary to Groq and stores the generated reasoning on the repo row.

The stored reasoning is displayed on the repo detail page.

### Email alerts

If SMTP settings are configured, critical findings trigger an email alert.

The email contains:

- repository name
- repository URL
- total findings
- critical findings
- top critical finding details
- AI summary
- immediate response guidance

The backend also records notification history in `critical_alert_notifications` so the same critical set is not sent repeatedly.

## Frontend behavior

The frontend uses Supabase browser auth helpers for session management. It:

- redirects unauthenticated users to `/login`
- fetches repository rows from Supabase
- calls the FastAPI backend to scan repositories
- fetches findings and clusters for display
- shows severity badges, exposure age, and exposure score

## Database tables

- `repos`
  - monitored GitHub repositories
  - status, scan time, finding count, AI reasoning
- `findings`
  - one row per detected secret instance
  - file path, line number, severity, snippet, hash, exposure data
- `clusters`
  - one row per shared secret hash
  - repo count and severity
- `critical_alert_notifications`
  - alert history and dedupe state for email notifications

## Runtime configuration

Backend environment variables:

- `SUPABASE_URL`
- `SUPABASE_KEY`
- `GROQ_API_KEY`
- `GITHUB_TOKEN`
- `HMAC_SECRET_KEY`
- `ENCRYPTION_KEY`
- `SMTP_HOST`
- `SMTP_PORT`
- `SMTP_USER`
- `SMTP_PASSWORD`
- `SMTP_USE_TLS`
- `SMTP_USE_SSL`
- `ALERT_EMAIL_FROM`
- `ALERT_EMAIL_TO`
- `ALLOWED_ORIGINS`

Frontend environment variables:

- `NEXT_PUBLIC_SUPABASE_URL`
- `NEXT_PUBLIC_SUPABASE_ANON_KEY`
- `NEXT_PUBLIC_API_URL`

## Operational notes

- Public GitHub repos are the intended scanning target.
- GitHub rate limits can affect exposure lookup if `GITHUB_TOKEN` is missing.
- SMTP passwords copied with spaces can break Gmail authentication, so the backend now normalizes the password at runtime.
- The repo detail page shows exposure columns only when the backend returns exposure data.

