export type AlertStatus = "UNREAD" | "READ";

export interface Alert {
  id: string;
  finding_id: string;
  title: string;
  message: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  status: AlertStatus;
  risk_score: number;
  pattern_type: string;
  matched_value: string;
  target_domain_match: boolean;
  created_at: string;
  read_at?: string | null;
  updated_at?: string | null;
}

