-- Fix all missing columns in alerts table
alter table if exists public.alerts 
    add column if not exists cooldown_key text,
    add column if not exists created_at timestamptz default now(),
    add column if not exists status text default 'UNREAD' check (status in ('UNREAD', 'READ', 'ARCHIVED')),
    add column if not exists severity text check (severity in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
    add column if not exists occurrence_count integer default 1,
    add column if not exists escalation_level text default 'normal' check (escalation_level in ('normal', 'elevated', 'critical'));

-- Create indexes for performance
create index if not exists idx_alerts_cooldown_key on public.alerts (cooldown_key);
create index if not exists idx_alerts_created_at on public.alerts (created_at desc);
create index if not exists idx_alerts_status on public.alerts (status);
create index if not exists idx_alerts_severity on public.alerts (severity);

-- Add comments for documentation
comment on column public.alerts.cooldown_key is 'Key used to prevent duplicate alerts within cooldown period';
comment on column public.alerts.created_at is 'Timestamp when the alert was created';
comment on column public.alerts.status is 'Alert status: UNREAD, READ, or ARCHIVED';
comment on column public.alerts.severity is 'Alert severity level';
comment on column public.alerts.occurrence_count is 'Number of times this alert has occurred';
comment on column public.alerts.escalation_level is 'Alert escalation level: normal, elevated, or critical';
