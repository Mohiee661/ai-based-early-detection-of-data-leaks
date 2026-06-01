# DarkShield Features

DarkShield scans GitHub repositories for exposed secrets, stores findings in Supabase, and helps you prioritize the riskiest leaks.

## Authentication

- Users sign in with Supabase Auth on `/login`.
- The frontend uses the logged-in session to scope repository data to the current user.

## Repository monitoring

- The `/` page lists every repository the user added.
- Adding a repository stores its owner, name, and GitHub URL in Supabase.
- The backend scans the repository after it is added or when the user clicks `Scan Now`.

## Secret scanning

- The backend fetches the repository file tree from GitHub.
- It skips large or irrelevant binary-like files.
- Each file is scanned line by line with regex patterns for common secret formats.
- Matched values are hashed so the same secret can be recognized across repositories.

## Severity levels

- Each regex pattern has a severity level assigned in the backend.
- Examples:
  - AWS secret keys and private keys are marked `critical`
  - OpenAI, Anthropic, Groq, GitHub, and Stripe-style tokens are usually `high`
  - generic password or secret patterns are usually `medium`
- The severity comes from the secret type that matched, not from machine learning.
- That severity is used in the UI and also in the exposure score calculation.

## Finding storage

- Every match becomes a `findings` row in Supabase.
- Each finding stores:
  - file path
  - line number
  - secret type
  - severity
  - snippet
  - secret hash
  - cluster link
  - exposure metadata when available

## Exposure time and exposure score

- The backend tries to find the first commit date for the file through the GitHub commits API.
- `exposure_days` is the number of days since that first commit.
- `exposure_score` is calculated as severity weight multiplied by `log2(exposure_days + 2)`.
- The repo detail page shows both values in the findings table.
- If older rows do not already have these fields, the API backfills them when possible.

## Groq reasoning

- After a scan, the backend sends a short summary to Groq when `GROQ_API_KEY` is configured.
- Groq returns a plain-English security summary.
- The repo detail page shows that reasoning in the AI analysis card.

## Cross-repo clustering

- Identical secret hashes are grouped into clusters.
- A cluster is considered interesting when the same secret appears in more than one repository.
- The `/clusters` page shows those shared secrets and how many repos are affected.

## Email alerts

- If SMTP settings are configured, the backend emails critical findings.
- The email includes the repo name, repo URL, critical findings, and the AI summary.
- Sent alerts are recorded in `critical_alert_notifications` so the same alert set is not sent twice.

## Repo detail page

The `/repos/[id]` page combines all of the above:

- repository status
- Groq reasoning
- total secrets
- critical count
- cross-repo cluster count
- findings table
- exposure time
- exposure score
- cluster warning banner

## What the backend depends on

- Supabase for auth and storage
- GitHub API for repository contents and commit history
- Groq for reasoning summaries
- SMTP for alert emails

## How the pieces work together

1. A user adds a GitHub repository.
2. The backend scans the repo and extracts secrets.
3. Findings are stored in Supabase.
4. Exposure age and score are calculated when commit history is available.
5. Groq generates a short summary.
6. Shared secret hashes are grouped into clusters.
7. Critical findings trigger an email alert if SMTP is valid.
