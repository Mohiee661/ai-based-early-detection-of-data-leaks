begin;

-- DarkShield full schema from scratch
-- This script clears the existing project tables and recreates the schema
-- in one pass so you can paste it directly into the Supabase SQL editor.

-- -------------------------------------------------------------------
-- Drop existing tables
-- -------------------------------------------------------------------

drop table if exists public.case_notes cascade;
drop table if exists public.case_alerts cascade;
drop table if exists public.case_findings cascade;
drop table if exists public.cases cascade;
drop table if exists public.alerts cascade;
drop table if exists public.critical_alert_notifications cascade;
drop table if exists public.findings cascade;
drop table if exists public.clusters cascade;
drop table if exists public.repos cascade;
drop table if exists public.raw_pages cascade;
drop table if exists public.scan_targets cascade;

drop function if exists public.set_updated_at() cascade;

-- -------------------------------------------------------------------
-- Extensions and helpers
-- -------------------------------------------------------------------

create extension if not exists pgcrypto;

create or replace function public.set_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

-- -------------------------------------------------------------------
-- Core tables
-- -------------------------------------------------------------------

create table public.repos (
  id               uuid primary key default gen_random_uuid(),
  user_id          uuid references auth.users(id) not null,
  github_url       text not null,
  owner            text not null,
  name             text not null,
  status           text not null default 'pending'
                   check (status in ('pending', 'scanning', 'done', 'error')),
  last_scanned_at  timestamptz,
  finding_count    int not null default 0,
  ai_reasoning     text,
  created_at       timestamptz not null default now(),
  updated_at       timestamptz not null default now(),
  unique (user_id, github_url),
  unique (user_id, owner, name)
);

create table public.clusters (
  id          uuid primary key default gen_random_uuid(),
  secret_hash text unique not null,
  secret_type text not null,
  repo_count  int not null default 1 check (repo_count >= 1),
  severity    text not null check (severity in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
  created_at  timestamptz not null default now()
);

create table public.raw_pages (
  id          uuid primary key default gen_random_uuid(),
  url         text not null,
  raw_text    text,
  fetched_at  timestamptz default now(),
  http_status integer,
  source_type text check (source_type in ('onion', 'paste', 'simulated', 'web', 'github', 'gitlab'))
);

create table public.scan_targets (
  id            uuid primary key default gen_random_uuid(),
  domain        text not null unique,
  email_pattern text,
  added_at      timestamptz default now(),
  is_active     boolean default true
);

create table public.findings (
  id                   uuid primary key default gen_random_uuid(),
  repo_id              uuid references public.repos(id) on delete cascade,
  raw_page_id          uuid references public.raw_pages(id) on delete set null,
  file_path            text not null,
  line_number          int not null check (line_number > 0),
  secret_type          text not null,
  severity             text not null check (severity in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
  snippet              text not null,
  secret_hash          text not null,
  cluster_id           uuid references public.clusters(id) on delete set null,
  source_type          text check (source_type in ('onion', 'paste', 'simulated', 'web', 'github', 'gitlab')),
  ai_label             text,
  ai_confidence        double precision,
  groq_summary         text,
  shap_explanation     jsonb,
  reasoning_summary    text,
  embedding_metadata   jsonb,
  classifier_metadata   jsonb,
  context_window       text,
  matched_value        text,
  target_domain_match  boolean not null default false,
  is_reviewed          boolean not null default false,
  created_at           timestamptz not null default now(),
  unique (repo_id, file_path, line_number, secret_hash)
);

create table public.alerts (
  id                  uuid primary key default gen_random_uuid(),
  finding_id          uuid references public.findings(id) on delete cascade,
  title               text not null,
  message             text not null,
  severity            text not null check (severity in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
  status              text not null default 'UNREAD'
                      check (status in ('UNREAD', 'READ', 'ARCHIVED')),
  risk_score          int not null default 0 check (risk_score >= 0 and risk_score <= 100),
  pattern_type        text not null,
  matched_value       text not null,
  target_domain_match  boolean not null default false,
  source_type         text,
  cluster_id          uuid references public.clusters(id) on delete set null,
  escalation_level    text not null default 'normal'
                      check (escalation_level in ('normal', 'elevated', 'critical')),
  occurrence_count    int not null default 1 check (occurrence_count >= 1),
  metadata            jsonb,
  cooldown_key        text,
  channel             text,
  sent_at             timestamptz default now(),
  read_at             timestamptz,
  created_at          timestamptz not null default now(),
  updated_at          timestamptz not null default now()
);

create table public.critical_alert_notifications (
  id              uuid primary key default gen_random_uuid(),
  repo_id         uuid not null references public.repos(id) on delete cascade,
  scan_signature  text not null,
  critical_count  int not null default 0 check (critical_count >= 0),
  total_count     int not null default 0 check (total_count >= 0),
  recipients      text[] not null default '{}'::text[],
  delivery_status text not null check (delivery_status in ('sent', 'failed', 'skipped')),
  error_message   text,
  created_at      timestamptz not null default now(),
  unique (repo_id, scan_signature)
);

create table public.cases (
  id                text primary key,
  title             text not null,
  description       text,
  severity          text not null default 'HIGH'
                    check (severity in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
  status            text not null default 'OPEN'
                    check (status in ('OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'FALSE_POSITIVE')),
  assigned_analyst  text,
  tags              text[] not null default '{}'::text[],
  created_at        timestamptz not null default now(),
  updated_at        timestamptz not null default now()
);

create table public.case_findings (
  id          text primary key,
  case_id     text not null references public.cases(id) on delete cascade,
  finding_id  uuid not null references public.findings(id) on delete cascade,
  created_at  timestamptz not null default now(),
  unique (case_id, finding_id)
);

create table public.case_alerts (
  id          text primary key,
  case_id     text not null references public.cases(id) on delete cascade,
  alert_id    uuid not null references public.alerts(id) on delete cascade,
  created_at  timestamptz not null default now(),
  unique (case_id, alert_id)
);

create table public.case_notes (
  id          text primary key,
  case_id     text not null references public.cases(id) on delete cascade,
  author      text not null,
  body        text not null,
  created_at  timestamptz not null default now()
);

-- -------------------------------------------------------------------
-- Indexes
-- -------------------------------------------------------------------

create index if not exists idx_repos_user_id on public.repos (user_id);
create index if not exists idx_repos_status on public.repos (status);
create index if not exists idx_repos_created_at on public.repos (created_at desc);

create index if not exists idx_clusters_secret_hash on public.clusters (secret_hash);
create index if not exists idx_clusters_repo_count on public.clusters (repo_count desc);
create index if not exists idx_clusters_severity on public.clusters (severity);

create index if not exists idx_raw_pages_url on public.raw_pages (url);
create index if not exists idx_raw_pages_source_type on public.raw_pages (source_type);
create index if not exists idx_raw_pages_fetched_at on public.raw_pages (fetched_at desc);

create index if not exists idx_scan_targets_domain on public.scan_targets (domain);
create index if not exists idx_scan_targets_is_active on public.scan_targets (is_active);

create index if not exists idx_findings_repo_id on public.findings (repo_id);
create index if not exists idx_findings_raw_page_id on public.findings (raw_page_id);
create index if not exists idx_findings_secret_hash on public.findings (secret_hash);
create index if not exists idx_findings_cluster_id on public.findings (cluster_id);
create index if not exists idx_findings_secret_type on public.findings (secret_type);
create index if not exists idx_findings_severity on public.findings (severity);
create index if not exists idx_findings_source_type on public.findings (source_type);
create index if not exists idx_findings_created_at on public.findings (created_at desc);
create index if not exists idx_findings_ai_label on public.findings (ai_label);
create index if not exists idx_findings_ai_confidence on public.findings (ai_confidence);
create index if not exists idx_findings_target_domain_match on public.findings (target_domain_match);

create index if not exists idx_alerts_finding_id on public.alerts (finding_id);
create index if not exists idx_alerts_cooldown_key on public.alerts (cooldown_key);
create index if not exists idx_alerts_matched_value on public.alerts (matched_value);
create index if not exists idx_alerts_pattern_type on public.alerts (pattern_type);
create index if not exists idx_alerts_severity on public.alerts (severity);
create index if not exists idx_alerts_status on public.alerts (status);
create index if not exists idx_alerts_created_at on public.alerts (created_at desc);
create index if not exists idx_alerts_updated_at on public.alerts (updated_at desc);

create index if not exists idx_critical_alert_notifications_repo_id on public.critical_alert_notifications (repo_id);
create index if not exists idx_critical_alert_notifications_signature on public.critical_alert_notifications (scan_signature);
create index if not exists idx_critical_alert_notifications_status on public.critical_alert_notifications (delivery_status);
create index if not exists idx_critical_alert_notifications_created_at on public.critical_alert_notifications (created_at desc);

create index if not exists idx_cases_status on public.cases (status);
create index if not exists idx_cases_severity on public.cases (severity);
create index if not exists idx_cases_updated_at on public.cases (updated_at desc);
create index if not exists idx_case_findings_case_id on public.case_findings (case_id);
create index if not exists idx_case_findings_finding_id on public.case_findings (finding_id);
create index if not exists idx_case_alerts_case_id on public.case_alerts (case_id);
create index if not exists idx_case_alerts_alert_id on public.case_alerts (alert_id);
create index if not exists idx_case_notes_case_id on public.case_notes (case_id);
create index if not exists idx_case_notes_created_at on public.case_notes (created_at desc);

-- -------------------------------------------------------------------
-- Triggers
-- -------------------------------------------------------------------

drop trigger if exists trg_repos_updated_at on public.repos;
create trigger trg_repos_updated_at
before update on public.repos
for each row
execute function public.set_updated_at();

drop trigger if exists trg_alerts_updated_at on public.alerts;
create trigger trg_alerts_updated_at
before update on public.alerts
for each row
execute function public.set_updated_at();

drop trigger if exists trg_cases_updated_at on public.cases;
create trigger trg_cases_updated_at
before update on public.cases
for each row
execute function public.set_updated_at();

-- -------------------------------------------------------------------
-- Row Level Security
-- -------------------------------------------------------------------

alter table public.repos enable row level security;
alter table public.clusters enable row level security;
alter table public.findings enable row level security;
alter table public.critical_alert_notifications enable row level security;

-- repos
drop policy if exists "Users see own repos" on public.repos;
create policy "Users see own repos"
on public.repos
for all
using (auth.uid() = user_id)
with check (auth.uid() = user_id);

-- findings
drop policy if exists "Users see own findings" on public.findings;
create policy "Users see own findings"
on public.findings
for all
using (
  exists (
    select 1
    from public.repos r
    where r.id = findings.repo_id
      and r.user_id = auth.uid()
  )
)
with check (
  exists (
    select 1
    from public.repos r
    where r.id = findings.repo_id
      and r.user_id = auth.uid()
  )
);

-- clusters
drop policy if exists "Clusters readable by authenticated users" on public.clusters;
create policy "Clusters readable by authenticated users"
on public.clusters
for select
using (auth.role() = 'authenticated');

-- critical alert notifications
drop policy if exists "Critical alert notifications selectable by owner" on public.critical_alert_notifications;
create policy "Critical alert notifications selectable by owner"
on public.critical_alert_notifications
for select
using (
  exists (
    select 1
    from public.repos r
    where r.id = critical_alert_notifications.repo_id
      and r.user_id = auth.uid()
  )
);

drop policy if exists "Critical alert notifications insertable by owner" on public.critical_alert_notifications;
create policy "Critical alert notifications insertable by owner"
on public.critical_alert_notifications
for insert
with check (
  exists (
    select 1
    from public.repos r
    where r.id = critical_alert_notifications.repo_id
      and r.user_id = auth.uid()
  )
);

drop policy if exists "Critical alert notifications updatable by owner" on public.critical_alert_notifications;
create policy "Critical alert notifications updatable by owner"
on public.critical_alert_notifications
for update
using (
  exists (
    select 1
    from public.repos r
    where r.id = critical_alert_notifications.repo_id
      and r.user_id = auth.uid()
  )
)
with check (
  exists (
    select 1
    from public.repos r
    where r.id = critical_alert_notifications.repo_id
      and r.user_id = auth.uid()
  )
);

drop policy if exists "Clusters insertable by authenticated users" on public.clusters;
create policy "Clusters insertable by authenticated users"
on public.clusters
for insert
with check (auth.role() = 'authenticated');

drop policy if exists "Clusters updatable by authenticated users" on public.clusters;
create policy "Clusters updatable by authenticated users"
on public.clusters
for update
using (auth.role() = 'authenticated')
with check (auth.role() = 'authenticated');

-- -------------------------------------------------------------------
-- Commit
-- -------------------------------------------------------------------

commit;
