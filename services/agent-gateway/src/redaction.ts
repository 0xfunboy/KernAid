const SECRET_PATTERNS = [
  /\b(?:sk|sk-ant)-[A-Za-z0-9_-]{8,}\b/g,
  /\bBearer\s+[A-Za-z0-9._~+/=-]{8,}\b/gi,
  /\bAIza[A-Za-z0-9_-]{20,}\b/g,
  /\b(?:OPENAI|ANTHROPIC|GEMINI|GOOGLE)_API_KEY\s*[:=]\s*[^\s]+/gi,
];

export function redactForProvider(input: string): string {
  return SECRET_PATTERNS.reduce(
    (redacted, pattern) => redacted.replace(pattern, "[REDACTED]"),
    input,
  );
}
