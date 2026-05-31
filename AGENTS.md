# AGENTS.md — DarkShield

## What this project does

User logs in → sees a list of GitHub repos they're monitoring → adds more repos →
clicks into any repo → sees a full AI-powered analysis of exposed secrets.
Cross-repo clustering groups the same leaked secret across multiple repos automatically.

---

## Pages (exactly 4)

| Route | Description |
|---|---|
| `/login` | Email + password login via Supabase Auth |
| `/` (repos list) | Cards for every added repo + "Add Repo" button |
| `/repos/[id]` | Full analysis for one repo |
| `/clusters` | Cross-repo clusters — secrets found in more than one repo |

No other pages. No sidebar needed — just a top navbar with the app name and a logout button.

---

## Stack

- **Frontend**: Next.js in `frontend/`
- **Backend**: Single FastAPI file `backend/main.py`
- **Auth + DB**: Supabase (handles login session automatically — no JWT code needed)
- **LLM**: Groq (`llama-3.3-70b-versatile` for reasoning)
- **Secret scanning**: regex patterns in Python, no ML libraries

---

## Database — run this SQL in Supabase SQL editor

```sql
create table if not exists repos (
  id              uuid primary key default gen_random_uuid(),
  user_id         uuid references auth.users not null,
  github_url      text not null,
  owner           text not null,
  name            text not null,
  status          text default 'pending',
  last_scanned_at timestamptz,
  finding_count   int default 0,
  ai_reasoning    text,
  created_at      timestamptz default now()
);

create table if not exists clusters (
  id          uuid primary key default gen_random_uuid(),
  secret_hash text unique not null,
  secret_type text not null,
  repo_count  int default 1,
  severity    text not null,
  created_at  timestamptz default now()
);

create table if not exists findings (
  id          uuid primary key default gen_random_uuid(),
  repo_id     uuid references repos not null,
  file_path   text not null,
  line_number int not null,
  secret_type text not null,
  severity    text not null,
  snippet     text not null,
  secret_hash text not null,
  cluster_id  uuid references clusters,
  created_at  timestamptz default now()
);

alter table repos     enable row level security;
alter table findings  enable row level security;
alter table clusters  enable row level security;

create policy "Users see own repos"     on repos     for all using (auth.uid() = user_id);
create policy "Users see own findings"  on findings  for all
  using (repo_id in (select id from repos where user_id = auth.uid()));
create policy "Clusters readable by authenticated users" on clusters
  for select using (auth.role() = 'authenticated');
```

---

## Backend — `backend/main.py` (complete implementation)

Replace the entire file with this:

```python
import hashlib, os, re
import httpx
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from supabase import create_client, Client
from groq import Groq

SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_KEY = os.environ["SUPABASE_KEY"]   # service role key
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
groq_client = Groq(api_key=GROQ_API_KEY) if GROQ_API_KEY else None

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("ALLOWED_ORIGINS", "http://localhost:3000").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)

PATTERNS = {
    "AWS Access Key":   (r'AKIA[0-9A-Z]{16}',                                          "high"),
    "AWS Secret Key":   (r'(?i)aws.{0,20}secret.{0,20}[\'"][0-9a-zA-Z/+=]{40}[\'"]',  "critical"),
    "OpenAI Key":       (r'sk-[a-zA-Z0-9]{32,}',                                       "high"),
    "Anthropic Key":    (r'sk-ant-[a-zA-Z0-9\-]{90,}',                                 "high"),
    "Groq Key":         (r'gsk_[a-zA-Z0-9]{50,}',                                      "high"),
    "GitHub Token":     (r'gh[pousr]_[A-Za-z0-9_]{36,}',                               "high"),
    "Stripe Secret":    (r'sk_live_[0-9a-zA-Z]{24,}',                                  "critical"),
    "Google API Key":   (r'AIza[0-9A-Za-z\-_]{35}',                                    "high"),
    "Slack Token":      (r'xox[baprs]-[0-9a-zA-Z\-]{10,}',                             "medium"),
    "Private Key":      (r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----',            "critical"),
    "Generic Password": (r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']?[^\s"\']{8,}["\']?', "medium"),
    "Generic Secret":   (r'(?i)(secret|api_key|api_secret|access_token)\s*[:=]\s*["\']?[^\s"\']{8,}["\']?', "medium"),
}

SKIP_EXT = {".png",".jpg",".gif",".svg",".ico",".woff",".ttf",
            ".zip",".pdf",".lock",".min.js",".map",".exe",".bin"}


class ScanRequest(BaseModel):
    repo_id: str


@app.post("/scan")
async def scan_repo(req: ScanRequest):
    row = supabase.table("repos").select("*").eq("id", req.repo_id).single().execute()
    if not row.data:
        raise HTTPException(404, "Repo not found")
    repo = row.data
    owner, name = repo["owner"], repo["name"]

    supabase.table("repos").update({"status": "scanning"}).eq("id", req.repo_id).execute()

    headers = {"Accept": "application/vnd.github+json"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"

    findings_raw = []

    async with httpx.AsyncClient(timeout=30) as client:
        tree_resp = await client.get(
            f"https://api.github.com/repos/{owner}/{name}/git/trees/HEAD?recursive=1",
            headers=headers,
        )
        if tree_resp.status_code != 200:
            supabase.table("repos").update({"status": "error"}).eq("id", req.repo_id).execute()
            raise HTTPException(400, "Could not fetch repo. Is it public?")

        files = [
            f for f in tree_resp.json().get("tree", [])
            if f["type"] == "blob"
            and f.get("size", 0) < 300_000
            and not any(f["path"].endswith(ext) for ext in SKIP_EXT)
        ]

        for file in files[:200]:
            url = f"https://raw.githubusercontent.com/{owner}/{name}/HEAD/{file['path']}"
            try:
                resp = await client.get(url, timeout=10)
                if resp.status_code != 200:
                    continue
                for i, line in enumerate(resp.text.splitlines(), 1):
                    for secret_type, (pattern, severity) in PATTERNS.items():
                        m = re.search(pattern, line)
                        if m:
                            secret_hash = hashlib.sha256(m.group(0).encode()).hexdigest()
                            findings_raw.append({
                                "repo_id":     req.repo_id,
                                "file_path":   file["path"],
                                "line_number": i,
                                "secret_type": secret_type,
                                "severity":    severity,
                                "snippet":     line.strip()[:120],
                                "secret_hash": secret_hash,
                            })
            except Exception:
                continue

    # Deduplicate within this repo scan
    seen, unique = set(), []
    for f in findings_raw:
        key = (f["secret_hash"], f["file_path"])
        if key not in seen:
            seen.add(key)
            unique.append(f)

    # Clustering — link each finding to a cluster row
    for finding in unique:
        h = finding["secret_hash"]
        existing = supabase.table("clusters").select("id,repo_count").eq("secret_hash", h).execute()
        if existing.data:
            cluster = existing.data[0]
            finding["cluster_id"] = cluster["id"]
            # Check if a DIFFERENT repo already has this hash
            other = (supabase.table("findings")
                     .select("repo_id")
                     .eq("secret_hash", h)
                     .neq("repo_id", req.repo_id)
                     .execute())
            if other.data:
                supabase.table("clusters").update(
                    {"repo_count": cluster["repo_count"] + 1}
                ).eq("id", cluster["id"]).execute()
        else:
            new_c = supabase.table("clusters").insert({
                "secret_hash": h,
                "secret_type": finding["secret_type"],
                "severity":    finding["severity"],
                "repo_count":  1,
            }).execute()
            finding["cluster_id"] = new_c.data[0]["id"]

    if unique:
        supabase.table("findings").insert(unique).execute()

    # Groq reasoning
    ai_reasoning = ""
    if groq_client and unique:
        type_counts: dict[str, int] = {}
        for f in unique:
            type_counts[f["secret_type"]] = type_counts.get(f["secret_type"], 0) + 1
        breakdown = ", ".join(f"{v}x {k}" for k, v in sorted(type_counts.items(), key=lambda x: -x[1]))
        critical_count = sum(1 for f in unique if f["severity"] == "critical")
        cross_repo = sum(
            1 for f in unique
            if supabase.table("findings").select("id")
               .eq("secret_hash", f["secret_hash"])
               .neq("repo_id", req.repo_id)
               .execute().data
        )
        try:
            chat = groq_client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a senior security analyst. Think step by step inside "
                            "<thinking> tags, then write a plain-English summary under 120 words."
                        ),
                    },
                    {
                        "role": "user",
                        "content": (
                            f"GitHub repo {owner}/{name} scan:\n"
                            f"- Total secrets exposed: {len(unique)}\n"
                            f"- Critical severity: {critical_count}\n"
                            f"- Types: {breakdown}\n"
                            f"- Also leaked in other monitored repos: {cross_repo}\n\n"
                            "What is the risk level, what are the most urgent actions, "
                            "and what does cross-repo leakage imply?"
                        ),
                    },
                ],
                max_tokens=350,
            )
            raw = chat.choices[0].message.content.strip()
            # Keep only the final summary, strip the thinking chain
            ai_reasoning = raw.split("</thinking>")[-1].strip() if "</thinking>" in raw else raw
        except Exception:
            ai_reasoning = "AI reasoning unavailable."

    supabase.table("repos").update({
        "status":          "done",
        "last_scanned_at": "now()",
        "finding_count":   len(unique),
        "ai_reasoning":    ai_reasoning,
    }).eq("id", req.repo_id).execute()

    return {"repo_id": req.repo_id, "total": len(unique), "ai_reasoning": ai_reasoning}


@app.get("/findings/{repo_id}")
async def get_findings(repo_id: str):
    data = supabase.table("findings").select("*").eq("repo_id", repo_id).execute()
    return data.data


@app.get("/clusters")
async def get_clusters():
    data = (supabase.table("clusters")
            .select("*")
            .gte("repo_count", 2)
            .order("repo_count", desc=True)
            .execute())
    return data.data


@app.get("/health")
async def health():
    return {"status": "ok"}
```

---

## Backend `requirements.txt`

```
fastapi
uvicorn
httpx
groq
supabase
pydantic
python-dotenv
```

---

## Frontend — page by page

### Supabase client setup

Install: `npm install @supabase/supabase-js @supabase/auth-helpers-nextjs`

Create `frontend/src/lib/supabase.ts`:
```ts
import { createBrowserClient } from '@supabase/auth-helpers-nextjs'

export const supabase = createBrowserClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!
)
```

### `/login`
- Centered card: "DarkShield" title, email input, password input, "Sign In" button.
- On submit: `supabase.auth.signInWithPassword({ email, password })`.
- On success: `router.push('/')`.
- No sign-up form — create accounts manually in Supabase dashboard → Authentication → Add User.

### `/` — Repos list
- On load: check `supabase.auth.getSession()`, redirect to `/login` if null.
- Top navbar: "DarkShield" left, "Clusters" link + "Sign Out" button right.
- "Add Repo" button → modal with one GitHub URL input.
  - Parse `owner` and `name` from the URL.
  - Insert into `repos` via Supabase client with `user_id = session.user.id`.
  - Then POST `{ repo_id }` to `NEXT_PUBLIC_API_URL/scan`.
- Repo cards grid (3 col desktop / 1 col mobile). Each card:
  - Repo name and owner as `owner/name`
  - Status badge: pending (gray) / scanning (blue, pulsing) / done (green) / error (red)
  - Finding count — colour: 0 = green, 1–5 = yellow, 6+ = red
  - "Last scanned" relative time (e.g. "2 hours ago")
  - "Scan Now" button — re-posts to `/scan`, sets card status to scanning
  - Clicking the card body navigates to `/repos/[id]`

### `/repos/[id]` — Repo detail
Layout top to bottom:
1. Back arrow + `owner/name` heading + external GitHub link icon
2. "Scan Now" button (top right)
3. **AI Reasoning card** — dark background card, robot icon, label "Groq Analysis", shows `ai_reasoning` text. Hidden if empty.
4. **Stats row** — three small metric cards: Total Secrets | Critical | Cross-repo Clusters
5. **Findings table** — filter tabs (All / Critical / High / Medium). Columns:
   - Severity (coloured badge: critical=red, high=orange, medium=yellow)
   - Type (secret type name)
   - File (monospace, truncated with tooltip)
   - Line (number)
   - Snippet (monospace, max 100 chars)
6. **Clusters warning** — shown only if any finding has a `cluster_id` that maps to `repo_count >= 2`. Yellow banner: "⚠ {n} secret(s) in this repo also appear in other monitored repos. View Clusters →"

Data fetching:
- Repo: `supabase.from('repos').select('*').eq('id', id).single()`
- Findings: `GET /findings/{id}` from backend

### `/clusters` — Clusters page
- Fetches `GET /clusters` from `NEXT_PUBLIC_API_URL/clusters`.
- Banner at top: "A cluster means the exact same secret key was found in multiple repos. Rotate it immediately."
- Table columns: Secret Type | Severity | Repos Affected | First Seen
- Rows with `repo_count >= 3` highlighted in red background.

---

## Env vars

### `backend/.env.example`
```
# Supabase dashboard → Settings → API
SUPABASE_URL=https://your-project.supabase.co
# Use the service_role key here (NOT anon) — backend needs to bypass RLS
SUPABASE_KEY=eyJ...

# Free at https://console.groq.com/keys — no credit card needed
GROQ_API_KEY=gsk_...

# Optional — only needed if you hit GitHub rate limits (60/hr without token, 5000/hr with)
# Get at https://github.com/settings/tokens → Generate new token (classic) → no scopes needed
GITHUB_TOKEN=ghp_...

# Comma-separated list of allowed frontend origins
ALLOWED_ORIGINS=http://localhost:3000
```

### `frontend/.env.local.example`
```
# Supabase dashboard → Settings → API → URL
NEXT_PUBLIC_SUPABASE_URL=https://your-project.supabase.co

# Supabase dashboard → Settings → API → anon/public key (safe to expose in browser)
NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJ...

# Your FastAPI backend URL (no trailing slash)
# Local: http://localhost:8000
NEXT_PUBLIC_API_URL=http://localhost:8000
```

---

## How clustering works

1. A secret like `sk-abc123` is found in Repo A.
2. Backend computes `SHA256("sk-abc123")` → hash `"a1b2c3..."`.
3. A new row is inserted into `clusters` with `secret_hash = "a1b2c3..."` and `repo_count = 1`.
4. The finding row links to that cluster via `cluster_id`.
5. Later, Repo B is scanned. Same key found → same hash computed.
6. Backend finds the existing cluster row, checks if a finding with that hash exists for a DIFFERENT repo — it does, so `repo_count` is incremented to 2.
7. `/clusters` endpoint returns all clusters with `repo_count >= 2`.

No ML. No embeddings. Just SHA256. Identical secrets match, different secrets don't.

---

## Local run

```bash
# Step 1 — Run the SQL above in Supabase SQL editor (one time only)

# Step 2 — Create a user for login in Supabase dashboard
# Go to Authentication → Users → Add User → set email + password

# Step 3 — Backend
cd backend
pip install -r requirements.txt
cp .env.example .env        # fill in SUPABASE_URL, SUPABASE_KEY, GROQ_API_KEY
uvicorn main:app --reload   # http://localhost:8000

# Step 4 — Frontend
cd frontend
npm install
cp .env.local.example .env.local   # fill in Supabase keys + API URL
npm run dev                         # http://localhost:3000
```

---

## Completion checklist

- [ ] SQL schema applied in Supabase (repos, clusters, findings + RLS policies)
- [ ] `/login` uses `supabase.auth.signInWithPassword` — no custom auth code
- [ ] `/` shows repo cards, "Add Repo" modal inserts row and triggers `/scan`
- [ ] `/repos/[id]` shows Groq reasoning card, stats, findings table, clusters warning
- [ ] `/clusters` shows cross-repo clusters with `repo_count >= 2`
- [ ] `backend/main.py` is one file — no other Python files
- [ ] Groq output strips `<thinking>` block before storing
- [ ] Clustering uses SHA256 — no ML libraries
- [ ] Both env example files are complete with comments
- [ ] `npm run build` exits 0
