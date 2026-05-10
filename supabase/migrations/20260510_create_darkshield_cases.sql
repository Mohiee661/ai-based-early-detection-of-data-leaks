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

create table if not exists public.case_findings (
    id text primary key,
    case_id text not null references public.cases(id) on delete cascade,
    finding_id text not null references public.findings(id) on delete cascade,
    created_at timestamptz not null default now(),
    unique (case_id, finding_id)
);

create table if not exists public.case_alerts (
    id text primary key,
    case_id text not null references public.cases(id) on delete cascade,
    alert_id text not null references public.alerts(id) on delete cascade,
    created_at timestamptz not null default now(),
    unique (case_id, alert_id)
);

create table if not exists public.case_notes (
    id text primary key,
    case_id text not null references public.cases(id) on delete cascade,
    author text not null,
    body text not null,
    created_at timestamptz not null default now()
);

create index if not exists idx_cases_status on public.cases (status);
create index if not exists idx_cases_severity on public.cases (severity);
create index if not exists idx_cases_updated_at on public.cases (updated_at desc);
create index if not exists idx_case_findings_case_id on public.case_findings (case_id);
create index if not exists idx_case_alerts_case_id on public.case_alerts (case_id);
create index if not exists idx_case_notes_case_id on public.case_notes (case_id);
