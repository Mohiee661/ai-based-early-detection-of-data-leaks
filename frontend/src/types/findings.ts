export type FindingMetadata = Record<string, unknown> & {
  explanation_source?: string;
  feature_importance?: Array<{ score: number; term: string }>;
  source_type?: string;
  summary_explanation?: string;
  summary_recommendation?: string;
  summary_source?: string;
  top_terms?: string[];
};

export interface Finding {
  id: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  pattern_type: string;
  matched_value: string;
  risk_score: number;
  created_at: string;
  context_window?: string;
  source_type?: string | null;
  ai_label?: string | null;
  ai_confidence?: number | null;
  groq_summary?: string | null;
  shap_explanation?: string | null;
  reasoning_summary?: string | null;
  embedding_metadata?: FindingMetadata | null;
  classifier_metadata?: FindingMetadata | null;
}
