const SECRET_PATTERNS = [
  /\b(?:sk|sk-ant)-[A-Za-z0-9_-]{8,}\b/g,
  /\bBearer\s+[A-Za-z0-9._~+/=-]{8,}\b/gi,
  /\bAIza[A-Za-z0-9_-]{20,}\b/g,
  /\b(?:OPENAI|ANTHROPIC|GEMINI|GOOGLE)_API_KEY\s*[:=]\s*[^\s]+/gi,
];

const PROVIDER_PII_PATTERNS = [
  /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}\b/gi,
  /\b(?:https?|ftp):\/\/[^\s<>"']+/gi,
  /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g,
  /\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b|\b[A-Fa-f0-9]{1,4}::(?:[A-Fa-f0-9]{1,4}:){0,6}[A-Fa-f0-9]{0,4}\b/g,
  /\b(?:[A-Fa-f0-9]{2}[:-]){5}[A-Fa-f0-9]{2}\b/g,
  /(?:\b[A-Za-z]:\\|\\\\)[^\s<>"'|]+/g,
  /(?:\/[A-Za-z0-9._~+-]+)+/g,
  /\b(?:user(?:name)?|account(?:name)?|owner)\b["']?\s*[:=]\s*["']?[-A-Za-z0-9._@\\]+/gi,
  /\b(?:serial(?:number)?|service[-_\s]*tag|machine[-_\s]*id|product[-_\s]*id|uuid|partuuid|ptuuid|wwn)\b["']?\s*[:=]\s*["']?[-A-Za-z0-9._:/\\]+/gi,
  /\b(?:host(?:name)?|computername)\b["']?\s*[:=]\s*["']?[-A-Za-z0-9._]+/gi,
];

export function redactSecretsForLocalEvidence(input: string): string {
  return SECRET_PATTERNS.reduce(
    (redacted, pattern) => redacted.replace(pattern, "[REDACTED]"),
    input,
  );
}

export function redactForProvider(input: string): string {
  return PROVIDER_PII_PATTERNS.reduce(
    (redacted, pattern) => redacted.replace(pattern, "[REDACTED]"),
    redactSecretsForLocalEvidence(input),
  );
}
