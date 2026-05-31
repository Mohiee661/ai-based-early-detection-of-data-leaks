-- Recreate alerts table with complete schema
drop table if exists public.alerts cascade;

create table public.alerts (
  id uuid primary key default gen_random_uuid(),
  finding_id uuid references public.findings(id) on delete cascade,
  channel text,
  sent_at timestamptz default now(),
  payload jsonb,
  cooldown_key text,
  matched_value text,
  pattern_type text,
  severity text check (severity in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
  status text default 'UNREAD' check (status in ('UNREAD', 'READ', 'ARCHIVED')),
  occurrence_count integer default 1,
  escalation_level text default 'normal' check (escalation_level in ('normal', 'elevated', 'critical'))
);

-- Create indexes
create index idx_alerts_finding_id on public.alerts (finding_id);
create index idx_alerts_channel on public.alerts (channel);
create index idx_alerts_sent_at on public.alerts (sent_at desc);
create index idx_alerts_cooldown_key on public.alerts (cooldown_key);
create index idx_alerts_matched_value on public.alerts (matched_value);
create index idx_alerts_pattern_type on public.alerts (pattern_type);
create index idx_alerts_severity on public.alerts (severity);
create index idx_alerts_status on public.alerts (status);

-- Add comments
comment on column public.alerts.id is 'Unique identifier for the alert';
comment on column public.alerts.finding_id is 'Reference to the finding that generated this alert';
comment on column public.alerts.channel is 'Channel where the alert was sent';
comment on column public.alerts.sent_at is 'Timestamp when the alert was sent';
comment on column public.alerts.payload is 'Additional payload data for the alert';
comment on column public.alerts.cooldown_key is 'Key used to prevent duplicate alerts within cooldown period';
comment on column public.alerts.matched_value is 'The matched value that triggered the alert';
comment on column public.alerts.pattern_type is 'Type of pattern that was matched';
comment on column public.alerts.severity is 'Alert severity level';
comment on column public.alerts.status is 'Alert status: UNREAD, READ, or ARCHIVED';
comment on column public.alerts.occurrence_count is 'Number of times this alert has occurred';
comment on column public.alerts.escalation_level is 'Alert escalation level: normal, elevated, or critical';
