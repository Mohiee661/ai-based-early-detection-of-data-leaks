export function parseGithubRepoUrl(input: string): {
  githubUrl: string;
  owner: string;
  name: string;
} {
  const value = input.trim();
  const normalized = value.startsWith("http://") || value.startsWith("https://")
    ? value
    : `https://${value}`;

  const parsed = new URL(normalized);
  if (parsed.hostname.toLowerCase() !== "github.com") {
    throw new Error("Please enter a public GitHub repository URL.");
  }

  const parts = parsed.pathname.split("/").filter(Boolean);
  if (parts.length < 2) {
    throw new Error("Please enter a URL like https://github.com/owner/repo.");
  }

  const owner = parts[0];
  const name = parts[1];
  return {
    githubUrl: `https://github.com/${owner}/${name}`,
    owner,
    name,
  };
}

export function formatRelativeTime(value: string | null | undefined): string {
  if (!value) {
    return "Never";
  }

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return "Unknown";
  }

  const diffSeconds = Math.round((date.getTime() - Date.now()) / 1000);
  const abs = Math.abs(diffSeconds);
  const rtf = new Intl.RelativeTimeFormat("en", { numeric: "auto" });

  if (abs < 60) {
    return rtf.format(Math.round(diffSeconds / 1), "second");
  }
  if (abs < 3600) {
    return rtf.format(Math.round(diffSeconds / 60), "minute");
  }
  if (abs < 86400) {
    return rtf.format(Math.round(diffSeconds / 3600), "hour");
  }
  return rtf.format(Math.round(diffSeconds / 86400), "day");
}
