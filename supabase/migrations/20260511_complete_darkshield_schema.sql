-- Complete DarkShield Schema Migration
-- This migration creates all tables with proper Supabase syntax

-- Create raw_pages table
create table if not exists public.raw_pages (
    id uuid primary key default gen_random_uuid(),
    url text not null,
    raw_text text,
    fetched_at timestamptz default now(),
    http_status integer,
    source_type text check (source_type in ('onion', 'paste', 'simulated'))
);

-- Create scan_targets table
create table if not exists public.scan_targets (
    id uuid primary key default gen_random_uuid(),
    domain text not null unique,
    email_pattern text,
    added_at timestamptz default now(),
    is_active boolean default true
);

-- Create findings table
create table if not exists public.findings (
    id uuid primary key default gen_random_uuid(),
    raw_page_id uuid references public.raw_pages(id) on delete set null,
    pattern_type text not null,
    matched_value text,
    context_window text,
    ai_label text,
    ai_confidence double precision,
    shap_explanation jsonb,
    groq_summary text,
    risk_score integer,
    severity text check (severity in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
    is_reviewed boolean default false,
    target_domain_match boolean default false,
    created_at timestamptz default now(),
    reasoning_summary text,
    embedding_metadata jsonb,
    classifier_metadata jsonb
);

-- Create alerts table
create table if not exists public.alerts (
    id uuid primary key default gen_random_uuid(),
    finding_id uuid references public.findings(id) on delete cascade,
    channel text,
    sent_at timestamptz default now(),
    payload jsonb
);

-- Create cases table
create table if not exists public.cases (
    id text primary key,
    title text not null,
    description text,
    severity text not null default 'HIGH' check (severity in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
    status text not null default 'OPEN' check (status in ('OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'FALSE_POSITIVE')),
    assigned_analyst text,
    tags text[] not null default '{}'::text[],
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

-- Create case_findings table
create table if not exists public.case_findings (
    id text primary key,
    case_id text not null references public.cases(id) on delete cascade,
    finding_id uuid not null references public.findings(id) on delete cascade,
    created_at timestamptz not null default now(),
    unique (case_id, finding_id)
);

-- Create case_alerts table
create table if not exists public.case_alerts (
    id text primary key,
    case_id text not null references public.cases(id) on delete cascade,
    alert_id uuid not null references public.alerts(id) on delete cascade,
    created_at timestamptz not null default now(),
    unique (case_id, alert_id)
);

-- Create case_notes table
create table if not exists public.case_notes (
    id text primary key,
    case_id text not null references public.cases(id) on delete cascade,
    author text not null,
    body text not null,
    created_at timestamptz not null default now()
);

-- Create indexes for performance
create index if not exists idx_raw_pages_url on public.raw_pages (url);
create index if not exists idx_raw_pages_source_type on public.raw_pages (source_type);
create index if not exists idx_raw_pages_fetched_at on public.raw_pages (fetched_at desc);

create index if not exists idx_scan_targets_domain on public.scan_targets (domain);
create index if not exists idx_scan_targets_is_active on public.scan_targets (is_active);

create index if not exists idx_findings_raw_page_id on public.findings (raw_page_id);
create index if not exists idx_findings_pattern_type on public.findings (pattern_type);
create index if not exists idx_findings_severity on public.findings (severity);
create index if not exists idx_findings_risk_score on public.findings (risk_score);
create index if not exists idx_findings_is_reviewed on public.findings (is_reviewed);
create index if not exists idx_findings_created_at on public.findings (created_at desc);
create index if not exists idx_findings_ai_label on public.findings (ai_label);
create index if not exists idx_findings_ai_confidence on public.findings (ai_confidence);

create index if not exists idx_alerts_finding_id on public.alerts (finding_id);
create index if not exists idx_alerts_channel on public.alerts (channel);
create index if not exists idx_alerts_sent_at on public.alerts (sent_at desc);

create index if not exists idx_cases_status on public.cases (status);
create index if not exists idx_cases_severity on public.cases (severity);
create index if not exists idx_cases_assigned_analyst on public.cases (assigned_analyst);
create index if not exists idx_cases_created_at on public.cases (created_at desc);
create index if not exists idx_cases_updated_at on public.cases (updated_at desc);

create index if not exists idx_case_findings_case_id on public.case_findings (case_id);
create index if not exists idx_case_findings_finding_id on public.case_findings (finding_id);

create index if not exists idx_case_alerts_case_id on public.case_alerts (case_id);
create index if not exists idx_case_alerts_alert_id on public.case_alerts (alert_id);

create index if not exists idx_case_notes_case_id on public.case_notes (case_id);
create index if not exists idx_case_notes_created_at on public.case_notes (created_at desc);

-- Add RLS (Row Level Security) policies if needed
-- Uncomment and modify these based on your security requirements

-- alter table public.raw_pages enable row level security;
-- alter table public.scan_targets enable row level security;
-- alter table public.findings enable row level security;
-- alter table public.alerts enable row level security;
-- alter table public.cases enable row level security;
-- alter table public.case_findings enable row level security;
-- alter table public.case_alerts enable row level security;
-- alter table public.case_notes enable row level security;

-- Example RLS policies (modify as needed)
-- create policy "Enable read access for authenticated users" on public.raw_pages for select using (auth.role() = 'authenticated');
-- create policy "Enable read access for authenticated users" on public.findings for select using (auth.role() = 'authenticated');
-- create policy "Enable read access for authenticated users" on public.alerts for select using (auth.role() = 'authenticated');
-- create policy "Enable read access for authenticated users" on public.cases for select using (auth.role() = 'authenticated');
-- create policy "Enable read access for authenticated users" on public.case_findings for select using (auth.role() = 'authenticated');
-- create policy "Enable read access for authenticated users" on public.case_alerts for select using (auth.role() = 'authenticated');
-- create policy "Enable read access for authenticated users" on public.case_notes for select using (auth.role() = 'authenticated');
