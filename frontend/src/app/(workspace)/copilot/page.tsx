"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { Bot, Copy, Download, Loader2, RefreshCcw, Send, Sparkles, Trash2 } from "lucide-react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

import { SeverityBadge } from "@/components/findings/severity-badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Textarea } from "@/components/ui/textarea";
import { useAuth } from "@/components/providers/auth-provider";
import {
  isApiConfigured,
  sendCopilotMessage,
  streamCopilotMessage,
  type CopilotMessage,
  type CopilotResponse,
} from "@/lib/api";
import { type Finding } from "@/types/findings";
import { cn } from "@/lib/utils";

type ChatEntry = CopilotMessage & {
  id: string;
  timestamp: string;
};

const STORAGE_KEYS = {
  messages: "darkshield-copilot-messages",
  recentQuestions: "darkshield-copilot-recent-questions",
  lastResponse: "darkshield-copilot-last-response",
} as const;

const suggestedPrompts = [
  "Show critical GitHub leaks",
  "Summarize today's findings",
  "What domains are most exposed?",
  "What API exposures are active?",
];

const quickActions = [
  "Show critical GitHub leaks",
  "Summarize today's findings",
  "What domains are most exposed?",
];

const initialMessages: ChatEntry[] = [
  {
    id: "seed-assistant",
    role: "assistant",
    content:
      "Ask me about critical findings, repeated exposures, active API leaks, or a specific domain.",
    timestamp: new Date().toISOString(),
  },
];

function formatTimestamp(timestamp: string) {
  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) {
    return "Unknown";
  }

  return new Intl.DateTimeFormat("en-US", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
}

function getHighestSeverity(findings: Finding[]) {
  const order: Finding["severity"][] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
  return order.find((severity) => findings.some((finding) => finding.severity === severity)) ?? "LOW";
}

function severityTone(severity: Finding["severity"] | undefined | null) {
  switch (severity) {
    case "CRITICAL":
      return "border-red-500/30 bg-red-500/5";
    case "HIGH":
      return "border-amber-500/30 bg-amber-500/5";
    case "MEDIUM":
      return "border-blue-500/30 bg-blue-500/5";
    default:
      return "border-border bg-card";
  }
}

function buildExportMarkdown(response: CopilotResponse | null, messages: ChatEntry[]) {
  const lines: string[] = [];
  lines.push("# DarkShield Copilot Export");
  lines.push("");
  lines.push(`Generated: ${new Date().toISOString()}`);
  lines.push("");
  lines.push("## Conversation");
  lines.push("");
  messages.forEach((message) => {
    lines.push(`### ${message.role === "user" ? "Analyst" : "Copilot"} - ${message.timestamp}`);
    lines.push("");
    lines.push(message.content);
    lines.push("");
  });

  if (response) {
    lines.push("## Response");
    lines.push("");
    lines.push(response.answer);
    lines.push("");
    lines.push("### Supporting Findings");
    lines.push("");
    response.supporting_findings.forEach((finding) => {
      lines.push(
        `- ${finding.severity} ${finding.pattern_type} | ${finding.matched_value} | risk ${finding.risk_score}`,
      );
    });
  }

  return lines.join("\n");
}

function extractIndicators(text: string) {
  const patterns = [
    /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,
    /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
    /\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b/gi,
    /\b(?:ghp_|gho_|ghs_|ghu_|sk-|xoxb-|AKIA)[A-Za-z0-9_-]{4,}\b/g,
  ];

  return Array.from(
    new Set(patterns.flatMap((pattern) => text.match(pattern) ?? [])),
  ).slice(0, 8);
}

function MarkdownMessage({ text }: { text: string }) {
  return (
    <ReactMarkdown
      remarkPlugins={[remarkGfm]}
      components={{
        p: ({ children }) => <p className="mb-2 last:mb-0 whitespace-pre-wrap text-sm leading-6 text-foreground">{children}</p>,
        strong: ({ children }) => <strong className="font-semibold text-foreground">{children}</strong>,
        em: ({ children }) => <em className="italic text-foreground">{children}</em>,
        ul: ({ children }) => <ul className="mb-2 ml-4 list-disc space-y-1 text-sm text-foreground">{children}</ul>,
        ol: ({ children }) => <ol className="mb-2 ml-4 list-decimal space-y-1 text-sm text-foreground">{children}</ol>,
        li: ({ children }) => <li className="leading-6 text-foreground">{children}</li>,
        code: ({ children }) => (
          <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-[0.8em] text-foreground">
            {children}
          </code>
        ),
        pre: ({ children }) => (
          <pre className="mb-2 overflow-x-auto rounded-[var(--radius)] border border-border bg-muted p-3 text-xs text-foreground">
            {children}
          </pre>
        ),
        a: ({ href, children }) => (
          <a className="text-primary underline decoration-primary/60 underline-offset-4" href={href} target="_blank" rel="noreferrer">
            {children}
          </a>
        ),
        blockquote: ({ children }) => (
          <blockquote className="mb-2 border-l-2 border-border pl-3 text-sm italic text-muted-foreground">
            {children}
          </blockquote>
        ),
        h1: ({ children }) => <h1 className="mb-2 text-base font-semibold text-foreground">{children}</h1>,
        h2: ({ children }) => <h2 className="mb-2 text-sm font-semibold text-foreground">{children}</h2>,
        h3: ({ children }) => <h3 className="mb-2 text-sm font-semibold text-foreground">{children}</h3>,
      }}
    >
      {text}
    </ReactMarkdown>
  );
}

function TypingIndicator() {
  return (
    <div className="flex items-center gap-2 rounded-[var(--radius)] border border-border bg-muted px-4 py-3 text-sm text-muted-foreground">
      <Loader2 className="size-4 animate-spin" />
      <span>Analyzing findings</span>
      <span className="inline-flex gap-1">
        <span className="animate-pulse">.</span>
        <span className="animate-pulse [animation-delay:120ms]">.</span>
        <span className="animate-pulse [animation-delay:240ms]">.</span>
      </span>
    </div>
  );
}

function MessageBubble({
  message,
}: {
  message: ChatEntry;
}) {
  const isUser = message.role === "user";
  return (
    <div className={cn("flex", isUser ? "justify-end" : "justify-start")}>
      <div
        className={cn(
          "max-w-[86%] rounded-[var(--radius)] border px-4 py-3 shadow-sm",
          isUser
            ? "border-border bg-foreground text-background"
            : "border-border bg-card text-foreground",
        )}
      >
        <div className="mb-2 flex items-center justify-between gap-3">
          <div className="text-[11px] uppercase tracking-[0.18em] text-muted-foreground">
            {isUser ? "Analyst" : "Copilot"}
          </div>
          <div className={cn("text-[11px]", isUser ? "text-background/70" : "text-muted-foreground")}>
            {formatTimestamp(message.timestamp)}
          </div>
        </div>

        {message.content.trim() ? (
          <MarkdownMessage text={message.content} />
        ) : (
          <div className="text-sm leading-6 text-muted-foreground">Generating response...</div>
        )}

        {!isUser ? (
          <div className="mt-3 flex flex-wrap gap-2">
            {extractIndicators(message.content).map((indicator) => (
              <span
                key={indicator}
                className="rounded-full border border-border bg-background px-2.5 py-1 text-[11px] text-foreground transition-colors hover:bg-accent/70"
              >
                {indicator}
              </span>
            ))}
          </div>
        ) : null}
      </div>
    </div>
  );
}

function FindingCard({
  finding,
  onReferenceClick,
}: {
  finding: Finding;
  onReferenceClick: (findingId: string) => void;
}) {
  return (
    <button
      id={`copilot-finding-${finding.id}`}
      type="button"
      onClick={() => onReferenceClick(finding.id)}
      className="w-full rounded-[var(--radius)] border border-border bg-background p-3 text-left transition-colors hover:bg-accent/60"
    >
      <div className="flex items-center justify-between gap-3">
        <SeverityBadge severity={finding.severity} />
        <span className="text-xs text-muted-foreground">{finding.risk_score} risk</span>
      </div>
      <div className="mt-3 text-sm font-medium text-foreground">{finding.pattern_type}</div>
      <div className="mt-1 break-all font-mono text-xs text-muted-foreground">{finding.matched_value}</div>
      <div className="mt-2 text-xs text-muted-foreground">
        {finding.ai_label ? `AI ${finding.ai_label}` : "AI unclassified"}
      </div>
      <div className="mt-1 text-xs text-muted-foreground">
        {finding.groq_summary || finding.reasoning_summary || "No AI summary available."}
      </div>
      <div className="mt-2 text-[11px] text-muted-foreground">{formatTimestamp(finding.created_at)}</div>
    </button>
  );
}

export default function CopilotPage() {
  const { status } = useAuth();
  const [messages, setMessages] = useState<ChatEntry[]>(initialMessages);
  const [draft, setDraft] = useState("");
  const [isSending, setIsSending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastResponse, setLastResponse] = useState<CopilotResponse | null>(null);
  const [recentQuestions, setRecentQuestions] = useState<string[]>([]);
  const [isHydrated, setIsHydrated] = useState(false);
  const [copied, setCopied] = useState(false);
  const conversationRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }

    const timeoutId = window.setTimeout(() => {
      try {
        const storedMessages = window.localStorage.getItem(STORAGE_KEYS.messages);
        const storedQuestions = window.localStorage.getItem(STORAGE_KEYS.recentQuestions);
        const storedResponse = window.localStorage.getItem(STORAGE_KEYS.lastResponse);

        if (storedMessages) {
          const parsed = JSON.parse(storedMessages) as ChatEntry[];
          if (Array.isArray(parsed) && parsed.length > 0) {
            setMessages(parsed);
            if (!storedQuestions) {
              const derivedQuestions = Array.from(
                new Set(
                  parsed
                    .filter((message) => message.role === "user")
                    .map((message) => message.content.trim())
                    .filter(Boolean),
                ),
              ).slice(-5).reverse();
              setRecentQuestions(derivedQuestions);
            }
          }
        }

        if (storedQuestions) {
          const parsedQuestions = JSON.parse(storedQuestions) as string[];
          if (Array.isArray(parsedQuestions)) {
            setRecentQuestions(parsedQuestions.filter((value) => typeof value === "string"));
          }
        }

        if (storedResponse) {
          const parsedResponse = JSON.parse(storedResponse) as CopilotResponse;
          setLastResponse(parsedResponse);
        }
      } catch {
        // Ignore persisted state failures and start fresh.
      } finally {
        setIsHydrated(true);
      }
    }, 0);

    return () => window.clearTimeout(timeoutId);
  }, []);

  useEffect(() => {
    if (!isHydrated || typeof window === "undefined") {
      return;
    }

    window.localStorage.setItem(STORAGE_KEYS.messages, JSON.stringify(messages));
    window.localStorage.setItem(STORAGE_KEYS.recentQuestions, JSON.stringify(recentQuestions));
    if (lastResponse) {
      window.localStorage.setItem(STORAGE_KEYS.lastResponse, JSON.stringify(lastResponse));
    }
  }, [isHydrated, lastResponse, messages, recentQuestions]);

  useEffect(() => {
    conversationRef.current?.scrollTo({
      top: conversationRef.current.scrollHeight,
      behavior: "smooth",
    });
  }, [messages, isSending]);

  const responseTone = severityTone(getHighestSeverity(lastResponse?.supporting_findings ?? []));
  const highlightedIndicators = useMemo(() => {
    const responseIndicators = lastResponse?.supporting_findings.flatMap((finding) => [
      finding.ai_label,
      finding.pattern_type,
      finding.matched_value,
    ]) ?? [];

    return Array.from(
      new Set(
        responseIndicators
          .filter((value): value is string => Boolean(value))
          .flatMap((value) => extractIndicators(value).concat([value])),
      ),
    ).slice(0, 10);
  }, [lastResponse]);

  async function copyResponse() {
    if (!lastResponse) {
      return;
    }

    const body = buildExportMarkdown(lastResponse, messages);
    await navigator.clipboard.writeText(body);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1500);
  }

  function exportResponse() {
    const body = buildExportMarkdown(lastResponse, messages);
    const file = new Blob([body], { type: "text/markdown;charset=utf-8" });
    const url = URL.createObjectURL(file);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `darkshield-copilot-${new Date().toISOString().replace(/[:.]/g, "-")}.md`;
    anchor.click();
    URL.revokeObjectURL(url);
  }

  function scrollToFinding(findingId: string) {
    const element = document.getElementById(`copilot-finding-${findingId}`);
    element?.scrollIntoView({ behavior: "smooth", block: "center" });
  }

  async function sendQuestion(question: string) {
    const trimmed = question.trim();
    if (!trimmed || isSending || status !== "authenticated") {
      return;
    }

    if (!isApiConfigured) {
      setError("Set NEXT_PUBLIC_API_URL in frontend/.env.local to enable the copilot.");
      return;
    }

    const nextMessages: ChatEntry[] = [
      ...messages,
      {
        id: `user-${crypto.randomUUID()}`,
        role: "user",
        content: trimmed,
        timestamp: new Date().toISOString(),
      },
      {
        id: `assistant-${crypto.randomUUID()}`,
        role: "assistant",
        content: "",
        timestamp: new Date().toISOString(),
      },
    ];

    setMessages(nextMessages);
    setRecentQuestions((current) => [trimmed, ...current.filter((item) => item !== trimmed)].slice(0, 5));
    setDraft("");
    setIsSending(true);
    setError(null);

    const assistantId = nextMessages[nextMessages.length - 1].id;
    const contextMessages = nextMessages
      .slice(0, -1)
      .map((message) => ({ role: message.role, content: message.content }));

    const updateAssistantMessage = (updater: (current: string) => string) => {
      setMessages((current) =>
        current.map((message) =>
          message.id === assistantId ? { ...message, content: updater(message.content) } : message,
        ),
      );
    };

    try {
      const response = await streamCopilotMessage(trimmed, contextMessages, {
        onChunk: (chunk) => updateAssistantMessage((current) => `${current}${chunk}`),
        onMeta: (meta) => setLastResponse(meta),
      });

      setLastResponse(response);
      updateAssistantMessage((current) => (current.trim() ? current : response.answer));
    } catch (streamError) {
      try {
        const response = await sendCopilotMessage(trimmed, contextMessages);
        setLastResponse(response);
        updateAssistantMessage(() => response.answer);
      } catch (submitError) {
        setError(
          submitError instanceof Error
            ? submitError.message
            : "Unable to generate a copilot response right now.",
        );
        setMessages((current) => current.filter((message) => message.id !== assistantId));
      }
      if (streamError instanceof Error) {
        // Preserve the fallback path; the UI should keep working even if streaming is unavailable.
        setError(null);
      }
    } finally {
      setIsSending(false);
    }
  }

  function clearConversation() {
    setMessages(initialMessages);
    setLastResponse(null);
    setError(null);
    setDraft("");
    setRecentQuestions([]);
    if (typeof window !== "undefined") {
      window.localStorage.removeItem(STORAGE_KEYS.messages);
      window.localStorage.removeItem(STORAGE_KEYS.recentQuestions);
      window.localStorage.removeItem(STORAGE_KEYS.lastResponse);
    }
  }

  return (
    <div className="grid gap-6 lg:grid-cols-[minmax(0,1.35fr)_minmax(320px,0.65fr)]">
      <section className="space-y-4">
        <Card className={cn("overflow-hidden border", responseTone)}>
          <CardHeader className="border-b border-border/70">
            <CardTitle className="flex items-center gap-2">
              <Bot className="size-4 text-muted-foreground" />
              Copilot
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex flex-wrap gap-2">
              {suggestedPrompts.map((prompt) => (
                <Button
                  key={prompt}
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => void sendQuestion(prompt)}
                  disabled={isSending || status !== "authenticated"}
                >
                  <Sparkles className="size-4" />
                  {prompt}
                </Button>
              ))}
            </div>
          </CardContent>
        </Card>

        <Card className="overflow-hidden">
          <CardHeader className="border-b border-border">
            <div className="flex items-center justify-between gap-3">
              <CardTitle className="text-base">Conversation</CardTitle>
              <div className="flex items-center gap-2">
                <Button variant="outline" size="sm" onClick={() => void copyResponse()} disabled={!lastResponse}>
                  <Copy className="size-4" />
                  {copied ? "Copied" : "Copy"}
                </Button>
                <Button variant="outline" size="sm" onClick={exportResponse} disabled={!lastResponse}>
                  <Download className="size-4" />
                  Export
                </Button>
                <Button variant="outline" size="sm" onClick={clearConversation}>
                  <Trash2 className="size-4" />
                  Clear
                </Button>
              </div>
            </div>
          </CardHeader>

          <CardContent className="space-y-4">
            <div ref={conversationRef} className="max-h-[34rem] space-y-3 overflow-y-auto pr-1">
                {messages.map((message) => (
                  <MessageBubble key={message.id} message={message} />
                ))}
              {isSending ? <TypingIndicator /> : null}
            </div>

            <form
              className="space-y-3 border-t border-border pt-4"
              onSubmit={(event) => {
                event.preventDefault();
                void sendQuestion(draft);
              }}
            >
              <Textarea
                value={draft}
                onChange={(event) => setDraft(event.target.value)}
                placeholder="Ask the copilot about critical GitHub leaks, API exposures, or daily findings..."
                className="min-h-28 resize-y"
              />
              {error ? <p className="text-sm text-red-400">{error}</p> : null}
              <div className="flex items-center justify-between gap-3">
                <p className="text-xs text-muted-foreground">Grounded in current data.</p>
                <Button type="submit" disabled={!draft.trim() || isSending || status !== "authenticated"}>
                  <Send className="size-4" />
                  Send
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>
      </section>

      <aside className="space-y-4">
        <Card className={cn("border", responseTone)}>
          <CardHeader>
            <CardTitle className="text-base">Summary</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3 text-sm leading-6 text-muted-foreground">
            <div className="flex flex-wrap items-center gap-2">
              <span className="rounded-full border border-border bg-background px-2.5 py-1 text-xs text-foreground">
                {lastResponse?.analysis_type ?? "No response yet"}
              </span>
            </div>
            <div>
              <span className="font-medium text-foreground">Confidence:</span>{" "}
              {lastResponse ? `${Math.round(lastResponse.confidence * 100)}%` : "Unknown"}
            </div>
            <div className="rounded-[var(--radius)] border border-border bg-background p-3">
              <MarkdownMessage text={lastResponse?.answer || "Submit a question to generate a copilot response."} />
            </div>
            <div className="space-y-2">
              <div className="text-xs font-medium uppercase tracking-[0.16em] text-muted-foreground">
                Indicators
              </div>
              <div className="flex flex-wrap gap-2">
                {highlightedIndicators.length > 0 ? (
                  highlightedIndicators.map((indicator) => (
                      <span
                        key={indicator}
                        className="rounded-full border border-border bg-background px-2.5 py-1 text-xs text-foreground transition-colors hover:bg-accent/70"
                      >
                        {indicator}
                      </span>
                    ))
                ) : (
                  <span className="text-xs text-muted-foreground">No highlighted indicators yet.</span>
                )}
              </div>
            </div>
            <div className="space-y-2">
              <div className="text-xs font-medium uppercase tracking-[0.16em] text-muted-foreground">
                Findings
              </div>
              <div className="flex flex-wrap gap-2">
                {lastResponse?.supporting_findings?.length ? (
                  lastResponse.supporting_findings.map((finding) => (
                    <button
                      key={finding.id}
                      type="button"
                      onClick={() => scrollToFinding(finding.id)}
                      className="rounded-full border border-border bg-background px-2.5 py-1 text-xs text-foreground transition-colors hover:bg-accent/70"
                    >
                      {finding.severity} {finding.pattern_type}
                    </button>
                  ))
                ) : (
                  <span className="text-xs text-muted-foreground">No finding references yet.</span>
                )}
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Actions</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {quickActions.map((prompt) => (
              <Button
                key={prompt}
                type="button"
                variant="outline"
                className="w-full justify-start"
                onClick={() => void sendQuestion(prompt)}
                disabled={isSending || status !== "authenticated"}
              >
                <RefreshCcw className="size-4" />
                {prompt}
              </Button>
            ))}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Recent</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {recentQuestions.length > 0 ? (
              recentQuestions.map((question) => (
                <button
                  key={question}
                  type="button"
                  onClick={() => void sendQuestion(question)}
                  className="w-full rounded-[var(--radius)] border border-border bg-background px-3 py-2 text-left text-sm text-foreground transition-colors hover:bg-accent/60"
                >
                  {question}
                </button>
              ))
            ) : (
              <p className="text-sm text-muted-foreground">
                Recent questions will appear here after the first query.
              </p>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Evidence</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {lastResponse?.supporting_findings?.length ? (
              lastResponse.supporting_findings.map((finding) => (
                <FindingCard key={finding.id} finding={finding} onReferenceClick={scrollToFinding} />
              ))
            ) : (
              <p className="text-sm text-muted-foreground">
                Findings surfaced by the copilot will appear here after the first query.
              </p>
            )}
          </CardContent>
        </Card>
      </aside>
    </div>
  );
}
