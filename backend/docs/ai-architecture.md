# DarkShield AI Architecture

## Overview

DarkShield uses a layered AI pipeline on top of the core findings workflow:

1. Pattern detection extracts candidate exposures from raw text.
2. Risk scoring assigns an operational severity and score.
3. The AI classifier labels the finding with a lightweight NLP model.
4. Summarization and reasoning turn the raw signal into analyst-readable output.
5. Explainability and embeddings add traceability and similarity support.
6. The frontend consumes the enriched data exclusively through FastAPI.

## Classifier Flow

- Input fields: `context_window`, `pattern_type`, `matched_value`
- Preprocessing: normalization, token cleanup, TF-IDF feature extraction
- Model: logistic regression over sparse text features
- Outputs: `ai_label`, `ai_confidence`, classifier metadata
- Artifacts: `backend/models/darkshield_ai_classifier.joblib`

## Summarization Flow

- Input fields: `context_window`, `pattern_type`, `severity`, `risk_score`
- Provider order: Groq, OpenAI, Ollama
- Fallback: deterministic summary when no model provider is configured
- Stored field: `groq_summary`

## Explainability Flow

- Uses SHAP when enabled with `ENABLE_SHAP=true`
- Falls back to coefficient-based top-term contributions by default
- Stores a human-readable explanation in `shap_explanation`
- Persists plot and JSON artifacts under `backend/models/explanations/`

## Reasoning Flow

- Combines AI label, severity, pattern type, source type, and risk score
- Produces remediation guidance and MITRE-style tags
- Stored field: `reasoning_summary`

## Similarity and Clustering

- Generates embeddings for context windows and summaries
- Uses sentence-transformers on CUDA when `ENABLE_GPU=true` and a CUDA build of PyTorch is available
- Falls back to TF-IDF embeddings otherwise
- Stores lightweight embedding metadata in the findings table
- The device selector logs whether the backend is using `cuda` or `cpu` at startup

## Analyst Copilot

- Protected endpoint: `POST /api/copilot/chat`
- Uses findings, dashboard metrics, and recent context
- Supports optional Groq/OpenAI/Ollama generation
- Falls back to deterministic operational summaries if no LLM is configured

## Deployment Notes

- Render hosts `backend/`
- Vercel hosts `frontend/`
- Supabase remains the system of record for findings and metadata
- The backend is designed to tolerate missing AI columns with safe fallbacks, but the recommended schema lives in `supabase/migrations/20260510_add_darkshield_ai_columns.sql`
