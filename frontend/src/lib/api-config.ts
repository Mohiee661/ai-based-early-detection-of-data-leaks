const apiBaseUrl =
  process.env.NEXT_PUBLIC_API_URL?.trim() || (process.env.NODE_ENV !== "production" ? "http://127.0.0.1:8001" : "");

export const isApiConfigured = Boolean(apiBaseUrl);

export function getApiBaseUrl() {
  if (!apiBaseUrl) {
    throw new Error("Missing NEXT_PUBLIC_API_URL.");
  }

  return apiBaseUrl.replace(/\/$/, "");
}
