-- Add missing source_type column to findings table
alter table if exists public.findings 
    add column if not exists source_type text check (source_type in ('onion', 'paste', 'simulated', 'github'));

-- Create index for performance
create index if not exists idx_findings_source_type on public.findings (source_type);

-- Add comment for documentation
comment on column public.findings.source_type is 'Source type where the finding was discovered';
