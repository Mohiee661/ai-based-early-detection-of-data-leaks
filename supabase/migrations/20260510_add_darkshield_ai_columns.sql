alter table if exists public.findings
    add column if not exists ai_label text,
    add column if not exists ai_confidence double precision,
    add column if not exists groq_summary text,
    add column if not exists shap_explanation text,
    add column if not exists reasoning_summary text,
    add column if not exists embedding_metadata jsonb,
    add column if not exists classifier_metadata jsonb;

create index if not exists findings_ai_label_idx on public.findings (ai_label);
create index if not exists findings_ai_confidence_idx on public.findings (ai_confidence);
