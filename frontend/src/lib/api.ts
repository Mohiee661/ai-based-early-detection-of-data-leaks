import { type Finding } from "@/types/findings";
import { type Alert, type AlertStatus } from "@/types/alerts";
import { clearAuthSession, getStoredAuthToken } from "@/lib/auth";
import { getApiBaseUrl } from "@/lib/api-config";

export { isApiConfigured } from "@/lib/api-config";

export type FindingsQueryParams = {
  page?: number;
  pageSize?: number;
  search?: string;
  severity?: Finding["severity"];
  sortBy?: "created_at" | "risk_score" | "severity" | "pattern_type";
  sortOrder?: "asc" | "desc";
};

export type FindingsQueryResponse = {
  items: Finding[];
  page: number;
  page_size: number;
  total: number;
  total_pages: number;
};

export type DashboardMetricsResponse = {
  api_key_exposures: number;
  critical_findings: number;
  findings_today: number;
  high_findings: number;
  total_findings: number;
};

export type LookupResponse = {
  count: number;
  items: Finding[];
  query: string;
};

export type SeverityBucket = {
  count: number;
  severity: Finding["severity"];
};

export type TimeSeriesPoint = {
  count: number;
  date: string;
};

export type PatternTypeBucket = {
  count: number;
  pattern_type: string;
};

export type AnalyticsSummaryResponse = {
  findings_over_time: TimeSeriesPoint[];
  severity_distribution: SeverityBucket[];
  top_pattern_types: PatternTypeBucket[];
};

export type CaseStatus = "OPEN" | "INVESTIGATING" | "CONTAINED" | "RESOLVED" | "FALSE_POSITIVE";

export type CaseNote = {
  author: string;
  body: string;
  case_id: string;
  created_at: string;
  id: string;
};

export type CaseSummary = {
  alert_count: number;
  assigned_analyst?: string | null;
  cluster_count: number;
  created_at: string;
  description?: string | null;
  finding_count: number;
  id: string;
  note_count: number;
  severity: Finding["severity"];
  status: CaseStatus;
  tags: string[];
  title: string;
  updated_at: string;
};

export type CaseActivity = {
  alert?: Alert | null;
  cluster?: TimelineCluster | null;
  finding?: Finding | null;
  id: string;
  activity_type:
    | "case_created"
    | "case_updated"
    | "case_note"
    | "finding_linked"
    | "alert_linked"
    | "finding_event"
    | "alert_event";
  severity?: Finding["severity"] | null;
  source_type?: string | null;
  summary?: string | null;
  timestamp: string;
  title: string;
  timeline_event?: TimelineEvent | null;
};

export type CaseDetail = CaseSummary & {
  activity_timeline: CaseActivity[];
  linked_alerts: Alert[];
  linked_findings: Finding[];
  notes: CaseNote[];
  related_clusters: TimelineCluster[];
};

export type CaseListResponse = {
  items: CaseSummary[];
  page: number;
  page_size: number;
  total: number;
  total_pages: number;
};

export type CaseCreatePayload = {
  alert_ids?: string[];
  assigned_analyst?: string | null;
  description?: string | null;
  finding_ids?: string[];
  severity?: Finding["severity"];
  status?: CaseStatus;
  tags?: string[];
  title: string;
};

export type CaseUpdatePayload = Partial<Omit<CaseCreatePayload, "finding_ids" | "alert_ids">>;

export type CaseAttachPayload = {
  ids: string[];
};

export type CaseNotePayload = {
  body: string;
};

export type TimelineRange = "7d" | "30d" | "90d" | "all";
export type TimelineGroupBy = "cluster" | "time";
export type TimelineEventType = "finding" | "github_exposure" | "alert" | "incident";

export type TimelineEvent = {
  alert_id?: string | null;
  cluster_id?: string | null;
  finding_id?: string | null;
  id: string;
  matched_value?: string | null;
  pattern_type?: string | null;
  related_count: number;
  severity: Finding["severity"];
  source_type: string;
  summary?: string | null;
  target_domain_match: boolean;
  timestamp: string;
  title: string;
  unread?: boolean | null;
  event_type: TimelineEventType;
};

export type TimelineCluster = {
  alert_count: number;
  alert_ids: string[];
  average_risk_score: number;
  average_similarity: number;
  cluster_id: string;
  finding_count: number;
  finding_ids: string[];
  first_seen: string;
  incident_count: number;
  incident_event_id?: string | null;
  last_seen: string;
  label: string;
  shared_indicators: string[];
  shared_keywords: string[];
  severity: Finding["severity"];
  severity_counts: Record<Finding["severity"], number>;
  source_types: string[];
  timeline: TimeSeriesPoint[];
};

export type ThreatTimelineResponse = {
  clusters: TimelineCluster[];
  events: TimelineEvent[];
  github_exposure_count: number;
  group_by: TimelineGroupBy;
  incident_count: number;
  range: TimelineRange;
  severity_filter: Finding["severity"] | null;
  total_alerts: number;
  total_events: number;
  total_findings: number;
};

export type DashboardSummary = {
  criticalCount: number;
  findings: Finding[];
  findingsToday: number;
  highCount: number;
  apiKeyExposureCount: number;
  totalFindings: number;
};

export type CopilotMessage = {
  content: string;
  role: "user" | "assistant";
};

export type CopilotRequest = {
  messages: CopilotMessage[];
  question: string;
};

export type CopilotResponse = {
  analysis_type: string;
  answer: string;
  confidence: number;
  conversation: CopilotMessage[];
  metrics: DashboardMetricsResponse | null;
  question: string;
  sources: string[];
  supporting_findings: Finding[];
};

export type CopilotStreamCallbacks = {
  onChunk?: (chunk: string) => void;
  onMeta?: (response: CopilotResponse) => void;
};

export type AlertsQueryParams = {
  page?: number;
  pageSize?: number;
  search?: string;
  severity?: Finding["severity"];
  status?: AlertStatus | "ALL";
};

export type AlertsQueryResponse = {
  items: Alert[];
  page: number;
  page_size: number;
  total: number;
  total_pages: number;
  unread_count: number;
};

async function requestJson<T>(path: string, init?: RequestInit): Promise<T> {
  const token = getStoredAuthToken();
  const response = await fetch(`${getApiBaseUrl()}${path}`, {
    ...init,
    headers: {
      Accept: "application/json",
      ...(init?.headers ?? {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    cache: "no-store",
  });

  if (!response.ok) {
    if (response.status === 401) {
      clearAuthSession();
      if (typeof window !== "undefined" && !window.location.pathname.startsWith("/login")) {
        window.location.assign(`/login?next=${encodeURIComponent(window.location.pathname)}`);
      }
    }

    let detail = `Request failed with status ${response.status}`;

    try {
      const payload = (await response.json()) as { detail?: string };
      if (typeof payload.detail === "string" && payload.detail.trim()) {
        detail = payload.detail;
      }
    } catch {
      // Ignore parse failures and surface the HTTP status instead.
    }

    throw new Error(detail);
  }

  return (await response.json()) as T;
}

function normalizeSeverity(severity: string | null | undefined): Finding["severity"] {
  switch ((severity ?? "").toUpperCase()) {
    case "CRITICAL":
      return "CRITICAL";
    case "HIGH":
      return "HIGH";
    case "MEDIUM":
      return "MEDIUM";
    default:
      return "LOW";
  }
}

function normalizeFinding(row: Partial<Finding> & { id?: string }, index: number): Finding {
  const riskScore = Number(row.risk_score ?? 0);
  const aiConfidence = row.ai_confidence == null ? null : Number(row.ai_confidence);
  return {
    id: row.id ?? `finding-${index}`,
    severity: normalizeSeverity(row.severity),
    pattern_type: row.pattern_type?.trim() || "Unknown Threat Type",
    matched_value: row.matched_value?.trim() || "N/A",
    risk_score: Number.isNaN(riskScore) ? 0 : riskScore,
    created_at: row.created_at ?? new Date().toISOString(),
    context_window: row.context_window?.trim() || undefined,
    source_type: row.source_type ?? row.classifier_metadata?.source_type ?? null,
    ai_label: row.ai_label ?? null,
    ai_confidence: aiConfidence == null || Number.isNaN(aiConfidence) ? null : aiConfidence,
    groq_summary: row.groq_summary ?? null,
    shap_explanation: row.shap_explanation ?? null,
    reasoning_summary: row.reasoning_summary ?? null,
    embedding_metadata: row.embedding_metadata ?? null,
    classifier_metadata: row.classifier_metadata ?? null,
  };
}

function buildQuery(params: FindingsQueryParams) {
  const query = new URLSearchParams();
  query.set("page", String(params.page ?? 1));
  query.set("page_size", String(params.pageSize ?? 50));
  query.set("sort_by", params.sortBy ?? "created_at");
  query.set("sort_order", params.sortOrder ?? "desc");

  if (params.search?.trim()) {
    query.set("search", params.search.trim());
  }

  if (params.severity?.trim()) {
    query.set("severity", params.severity.trim().toUpperCase());
  }

  return query.toString();
}

function buildAlertsQuery(params: AlertsQueryParams) {
  const query = new URLSearchParams();
  query.set("page", String(params.page ?? 1));
  query.set("page_size", String(params.pageSize ?? 20));

  if (params.search?.trim()) {
    query.set("search", params.search.trim());
  }

  if (params.severity?.trim()) {
    query.set("severity", params.severity.trim().toUpperCase());
  }

  if (params.status && params.status !== "ALL") {
    query.set("status", params.status);
  }

  return query.toString();
}

export async function getFindings(params: FindingsQueryParams = {}): Promise<FindingsQueryResponse> {
  const payload = await requestJson<FindingsQueryResponse>(`/api/findings?${buildQuery(params)}`);

  return {
    ...payload,
    items: payload.items.map((row, index) => normalizeFinding(row, index)),
  };
}

export async function getDashboardMetrics(): Promise<DashboardMetricsResponse> {
  return requestJson<DashboardMetricsResponse>("/api/dashboard/metrics");
}

export async function lookupIndicators(query: string): Promise<LookupResponse> {
  const normalized = query.trim();
  if (!normalized) {
    return {
      count: 0,
      items: [],
      query: normalized,
    };
  }

  const payload = await requestJson<LookupResponse>(
    `/api/lookup?q=${encodeURIComponent(normalized)}`,
  );

  return {
    ...payload,
    items: payload.items.map((row, index) => normalizeFinding(row, index)),
  };
}

export async function getAnalyticsSummary(): Promise<AnalyticsSummaryResponse> {
  return requestJson<AnalyticsSummaryResponse>("/api/analytics/summary");
}

export async function getCases(params: {
  page?: number;
  pageSize?: number;
  search?: string;
  severity?: Finding["severity"];
  status?: CaseStatus | "ALL";
} = {}): Promise<CaseListResponse> {
  const query = new URLSearchParams();
  query.set("page", String(params.page ?? 1));
  query.set("page_size", String(params.pageSize ?? 20));
  if (params.search?.trim()) {
    query.set("search", params.search.trim());
  }
  if (params.severity) {
    query.set("severity", params.severity);
  }
  if (params.status && params.status !== "ALL") {
    query.set("status", params.status);
  }
  return requestJson<CaseListResponse>(`/api/cases?${query.toString()}`);
}

export async function getCase(caseId: string): Promise<CaseDetail> {
  return requestJson<CaseDetail>(`/api/cases/${encodeURIComponent(caseId)}`);
}

export async function createCase(payload: CaseCreatePayload): Promise<CaseDetail> {
  return requestJson<CaseDetail>("/api/cases", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });
}

export async function updateCase(caseId: string, payload: CaseUpdatePayload): Promise<CaseDetail> {
  return requestJson<CaseDetail>(`/api/cases/${encodeURIComponent(caseId)}`, {
    method: "PATCH",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });
}

export async function attachCaseFindings(caseId: string, ids: string[]): Promise<CaseDetail> {
  return requestJson<CaseDetail>(`/api/cases/${encodeURIComponent(caseId)}/findings`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ ids } satisfies CaseAttachPayload),
  });
}

export async function attachCaseAlerts(caseId: string, ids: string[]): Promise<CaseDetail> {
  return requestJson<CaseDetail>(`/api/cases/${encodeURIComponent(caseId)}/alerts`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ ids } satisfies CaseAttachPayload),
  });
}

export async function addCaseNote(caseId: string, body: string): Promise<CaseNote> {
  return requestJson<CaseNote>(`/api/cases/${encodeURIComponent(caseId)}/notes`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ body } satisfies CaseNotePayload),
  });
}

export async function getThreatTimeline(params: {
  groupBy?: TimelineGroupBy;
  range?: TimelineRange;
  severity?: Finding["severity"];
} = {}): Promise<ThreatTimelineResponse> {
  const query = new URLSearchParams();
  query.set("range", params.range ?? "30d");
  query.set("group_by", params.groupBy ?? "cluster");
  if (params.severity) {
    query.set("severity", params.severity);
  }

  return requestJson<ThreatTimelineResponse>(`/api/investigations/timeline?${query.toString()}`);
}

export async function getAlerts(params: AlertsQueryParams = {}): Promise<AlertsQueryResponse> {
  return requestJson<AlertsQueryResponse>(`/api/alerts?${buildAlertsQuery(params)}`);
}

export async function markAlertRead(alertId: string): Promise<Alert> {
  return requestJson<Alert>(`/api/alerts/${encodeURIComponent(alertId)}/read`, {
    method: "PATCH",
  });
}

export async function markAllAlertsRead(): Promise<{ updated: number }> {
  return requestJson<{ updated: number }>("/api/alerts/read-all", {
    method: "POST",
  });
}

export async function getUnreadAlertCount(): Promise<{ unread_count: number }> {
  return requestJson<{ unread_count: number }>("/api/alerts/unread-count");
}

export async function getDashboardSummary(): Promise<DashboardSummary> {
  const [metrics, findings] = await Promise.all([
    getDashboardMetrics(),
    getFindings({ pageSize: 50, sortBy: "created_at", sortOrder: "desc" }),
  ]);

  return {
    findings: findings.items,
    totalFindings: metrics.total_findings,
    criticalCount: metrics.critical_findings,
    highCount: metrics.high_findings,
    findingsToday: metrics.findings_today,
    apiKeyExposureCount: metrics.api_key_exposures,
  };
}

export async function sendCopilotMessage(
  question: string,
  messages: CopilotMessage[] = [],
): Promise<CopilotResponse> {
  const payload = await requestJson<CopilotResponse>("/api/copilot/chat", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      question,
      messages,
    } satisfies CopilotRequest),
  });

  return {
    ...payload,
    supporting_findings: payload.supporting_findings.map((row, index) => normalizeFinding(row, index)),
  };
}

export async function streamCopilotMessage(
  question: string,
  messages: CopilotMessage[] = [],
  callbacks: CopilotStreamCallbacks = {},
): Promise<CopilotResponse> {
  const token = getStoredAuthToken();
  const response = await fetch(`${getApiBaseUrl()}/api/copilot/chat/stream`, {
    method: "POST",
    headers: {
      Accept: "text/event-stream",
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify({
      question,
      messages,
    } satisfies CopilotRequest),
    cache: "no-store",
  });

  if (!response.ok || !response.body) {
    if (response.status === 401) {
      clearAuthSession();
      if (typeof window !== "undefined" && !window.location.pathname.startsWith("/login")) {
        window.location.assign(`/login?next=${encodeURIComponent(window.location.pathname)}`);
      }
    }

    let detail = `Request failed with status ${response.status}`;
    try {
      const payload = (await response.json()) as { detail?: string };
      if (typeof payload.detail === "string" && payload.detail.trim()) {
        detail = payload.detail;
      }
    } catch {
      // Ignore parsing errors.
    }
    throw new Error(detail);
  }

  const decoder = new TextDecoder();
  const reader = response.body.getReader();
  let buffer = "";
  let finalResponse: CopilotResponse | null = null;

  function applyEvent(eventName: string, data: string) {
    if (!data.trim()) {
      return;
    }

    if (eventName === "chunk") {
      const payload = JSON.parse(data) as { chunk?: string };
      if (typeof payload.chunk === "string") {
        callbacks.onChunk?.(payload.chunk);
      }
      return;
    }

    if (eventName === "meta") {
      const payload = JSON.parse(data) as CopilotResponse;
      finalResponse = {
        ...payload,
        supporting_findings: (payload.supporting_findings ?? []).map((row, index) =>
          normalizeFinding(row, index),
        ),
      };
      callbacks.onMeta?.(finalResponse);
    }
  }

  while (true) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }

    buffer += decoder.decode(value, { stream: true });

    let separatorIndex = buffer.indexOf("\n\n");
    while (separatorIndex >= 0) {
      const eventBlock = buffer.slice(0, separatorIndex);
      buffer = buffer.slice(separatorIndex + 2);

      const lines = eventBlock.split("\n");
      let eventName = "message";
      const dataLines: string[] = [];

      lines.forEach((line) => {
        if (line.startsWith("event:")) {
          eventName = line.slice("event:".length).trim();
        } else if (line.startsWith("data:")) {
          dataLines.push(line.slice("data:".length).trim());
        }
      });

      if (dataLines.length > 0) {
        applyEvent(eventName, dataLines.join("\n"));
      }

      separatorIndex = buffer.indexOf("\n\n");
    }
  }

  if (!finalResponse) {
    throw new Error("Streaming response ended before metadata arrived.");
  }

  return finalResponse;
}
