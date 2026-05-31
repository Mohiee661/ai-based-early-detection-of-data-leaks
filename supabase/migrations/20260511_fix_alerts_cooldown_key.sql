-- Add missing cooldown_key column to alerts table
alter table if exists public.alerts 
    add column if not exists cooldown_key text;

-- Create index for performance
create index if not exists idx_alerts_cooldown_key on public.alerts (cooldown_key);

-- Add comments for documentation
comment on column public.alerts.cooldown_key is 'Key used to prevent duplicate alerts within cooldown period';
