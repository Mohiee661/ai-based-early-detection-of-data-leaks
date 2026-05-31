-- Add missing matched_value and other columns to alerts table
alter table if exists public.alerts 
    add column if not exists matched_value text,
    add column if not exists pattern_type text,
    add column if not exists severity text check (severity in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
    add column if not exists finding_id uuid references public.findings(id) on delete cascade,
    add column if not exists channel text,
    add column if not exists sent_at timestamptz default now(),
    add column if not exists payload jsonb,
    add column if not exists cooldown_key text,
    add column if not exists created_at timestamptz default now(),
    add column if not exists status text default 'UNREAD' check (status in ('UNREAD', 'READ', 'ARCHIVED')),
    add column if not exists occurrence_count integer default 1,
    add column if not exists escalation_level text default 'normal' check (escalation_level in ('normal', 'elevated', 'critical'));

-- Create indexes for performance
create index if not exists idx_alerts_matched_value on public.alerts (matched_value);
create index if not exists idx_alerts_pattern_type on public.alerts (pattern_type);
create index if not exists idx_alerts_finding_id on public.alerts (finding_id);
create index if not exists idx_alerts_cooldown_key on public.alerts (cooldown_key);
create index if not exists idx_alerts_created_at on public.alerts (created_at desc);
create index if not exists idx_alerts_status on public.alerts (status);
create index if not exists idx_alerts_severity on public.alerts (severity);

-- Add comments for documentation
comment on column public.alerts.matched_value is 'The matched value that triggered the alert';
comment on column public.alerts.pattern_type is 'Type of pattern that was matched';
comment on column public.alerts.severity is 'Alert severity level';
comment on column public.alerts.finding_id is 'Reference to the finding that generated this alert';
