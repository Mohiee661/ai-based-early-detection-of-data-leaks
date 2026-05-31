# DarkShield

DarkShield is a simplified demo that scans a public GitHub repository for exposed secrets and shows the results in a single-page frontend.

## What it does

- Paste a public GitHub repo URL into the frontend.
- The backend scans the repository files for secret patterns.
- If configured, Groq generates a short analyst summary.
- The frontend renders the findings in a table with severity badges.

## Stack

- Frontend: Next.js in `frontend/`
- Backend: FastAPI in `backend/main.py`
- APIs used: GitHub REST API, optional Groq API
- No database, no auth, no JWT

## Local Run

```powershell
# Backend
cd backend
pip install -r requirements.txt
cp .env.example .env   # add your GROQ_API_KEY if desired
uvicorn main:app --reload

# Frontend
cd frontend
npm install
cp .env.example .env.local
npm run dev

# Then open http://localhost:3000
# Paste any public GitHub URL and click Scan
```

## Environment Variables

### `backend/.env.example`

```env
GROQ_API_KEY=gsk_...
GITHUB_TOKEN=ghp_...
```

### `frontend/.env.example`

```env
NEXT_PUBLIC_API_URL=http://localhost:8000
```
