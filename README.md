# DarkShield

DarkShield is an AI-assisted threat intelligence platform for early detection of exposed credentials, API keys, suspicious domains, and related data leak indicators.

## Progress Summary

Current progress in the repo:

- A Python detection pipeline exists for pattern extraction, risk scoring, synthetic data generation, and findings processing into Supabase.
- A Streamlit dashboard exists for local backend monitoring and manual inspection.
- A production FastAPI layer now exposes findings, metrics, lookup, analytics, and health endpoints for the frontend.
- JWT auth now protects the dashboard API and workspace routes.
- A Next.js 16 analyst interface exists with dashboard, findings, lookup, alerts, analytics, and settings routes.
- A lightweight AI stack now adds classifier labels, summarization, reasoning, explainability, clustering metadata, and an analyst copilot.
- Supabase remains the backend data store, and the analyst UI now reaches it through FastAPI instead of direct browser queries.
- The repo is now arranged as a deployable monorepo: `frontend/` for Vercel and `backend/` for Render.

## Repository Layout

```text
.
|-- backend/
|   |-- api/                    # FastAPI routers, schemas, and services
|   |-- docs/                   # AI architecture notes and deployment references
|   |-- app/                    # Python detection pipeline and Supabase helpers
|   |-- pages/                  # Streamlit multipage views
|   |-- dashboard.py            # Streamlit dashboard entry
|   |-- main.py                 # FastAPI entry for Render
|   |-- requirements.txt        # Full local Python dependency set
|   |-- requirements-render.txt # Slim Render dependency set
|   `-- run_dashboard.py        # Local Streamlit launcher
|-- frontend/                   # Next.js analyst interface for Vercel
|-- render.yaml                 # Render Blueprint config
`-- README.md
```

## Architecture

```text
signals/raw pages -> backend pipeline -> Supabase -> FastAPI API -> frontend analyst UI
                                       -> Streamlit local dashboard
                                       -> AI enrichment + copilot services
```

## Backend

Key backend pieces:

- `backend/app/pattern_engine.py`
- `backend/app/risk_scorer.py`
- `backend/app/process_findings.py`
- `backend/app/simulate_data.py`
- `backend/app/db.py`
- `backend/main.py`

The FastAPI service exposes:

- `POST /api/auth/login`
- `GET /api/auth/me`
- `GET /health`
- `GET /api/findings`
- `GET /api/dashboard/metrics`
- `GET /api/lookup`
- `GET /api/analytics/summary`
- `POST /api/copilot/chat`

## AI Architecture

DarkShield now enriches findings with a layered AI pipeline:

- `backend/app/ai/classifier.py` trains and serves a lightweight TF-IDF + logistic regression classifier.
- `backend/app/ai/summarizer.py` generates concise analyst summaries with Groq, OpenAI, or Ollama fallbacks.
- `backend/app/ai/reasoning.py` adds operational reasoning and MITRE-style tags.
- `backend/app/ai/explainability.py` generates explanation text and artifacts.
- `backend/app/ai/clustering.py` prepares embeddings and similarity metadata.
- `backend/api/routes/copilot.py` exposes the analyst copilot over authenticated FastAPI.

The findings table now carries:

- `ai_label`
- `ai_confidence`
- `groq_summary`
- `shap_explanation`
- `reasoning_summary`
- `embedding_metadata`
- `classifier_metadata`

Model artifacts are stored under `backend/models/`, and the classifier can be trained or smoke-tested with:

```powershell
cd backend
python app/ai/classifier.py
```

## Frontend

The frontend lives in `frontend/` and is ready to deploy independently as a Next.js app.

Important files:

- `frontend/src/app/page.tsx`
- `frontend/src/app/(workspace)/dashboard/page.tsx`
- `frontend/src/app/(workspace)/findings/page.tsx`
- `frontend/src/app/(workspace)/lookup/page.tsx`
- `frontend/src/app/(workspace)/copilot/page.tsx`
- `frontend/src/lib/api.ts`

## Local Setup

### Backend

```powershell
cd backend
python -m venv venv
venv\Scripts\activate
python -m pip install -r requirements.txt
```

Backend environment variables can live in either:

- `backend/.env`
- repo root `.env`

Use `backend/.env.example` as the template.

Auth setup requires:

- `AUTH_USERNAME`
- `AUTH_DISPLAY_NAME`
- `AUTH_ROLE`
- `AUTH_PASSWORD_HASH`
- `AUTH_JWT_SECRET`
- `AUTH_ACCESS_TOKEN_MINUTES`

GPU acceleration for local AI is controlled with:

- `ENABLE_GPU=true`
- `ENABLE_SHAP=false` by default

If you want the RTX 4050 to handle embeddings and clustering locally, install the CUDA build of PyTorch inside the backend venv:

```powershell
cd backend
venv\Scripts\activate
pip uninstall torch torchvision torchaudio -y
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu121
```

Verify with:

```powershell
python -c "import torch; print(torch.cuda.is_available()); print(torch.cuda.get_device_name(0) if torch.cuda.is_available() else 'No GPU detected')"
```

If CUDA is unavailable, DarkShield falls back to CPU automatically and keeps the same API behavior.

### Frontend

```powershell
cd frontend
npm install
```

Use `frontend/.env.example` as the template for local frontend variables.

The frontend login screen is available at `/login`.

## Screenshots

Add screenshots here after deployment or demo capture:

- `docs/screenshots/dashboard.png`
- `docs/screenshots/findings.png`
- `docs/screenshots/copilot.png`

## Local Run Commands

### Backend API

```powershell
cd backend
uvicorn main:app --reload
```

### Streamlit Dashboard

```powershell
cd backend
python run_dashboard.py
```

### Frontend

```powershell
cd frontend
npm run dev
```

## Deployment

### Vercel

Deploy `frontend/` as its own Vercel project.

Required frontend environment variables:

- `NEXT_PUBLIC_API_URL`

### Render

Deploy the backend from the repo root using `render.yaml`, which points Render at `backend/`.

Required backend environment variables:

- `SUPABASE_URL`
- `SUPABASE_KEY`
- `ALLOWED_ORIGINS`
- `GROQ_API_KEY` if you want live LLM summarization
- `OPENAI_API_KEY` if you want OpenAI fallback
- `ENABLE_GPU=true` if you want local CUDA acceleration
- `ENABLE_SHAP=true` if you want SHAP explainability enabled

Default Render start command:

```text
uvicorn main:app --host 0.0.0.0 --port $PORT
```

## Next Steps

- Point the Vercel project at `frontend/`
- Create the Render service from `render.yaml`
- Add production Supabase credentials in Render and the API base URL in Vercel
- Set `ALLOWED_ORIGINS` to the deployed Vercel domain
- Apply `supabase/migrations/20260510_add_darkshield_ai_columns.sql`
- Decide which AI providers to enable in production
- Capture screenshots and drop them into the placeholders above

## Roadmap

- Add a persisted alert schema instead of the current synthetic fallback
- Surface related findings and clusters in the UI
- Extend the copilot with more question templates and workspace actions
- Add background jobs for scheduled AI enrichment and backfills
