export type SecretType =
  | "openai_api_key"
  | "anthropic_api_key"
  | "github_pat"
  | "aws_access_key"
  | "private_key"
  | "ssh_private_key"
  | "credential_assignment";

export interface SecretScanResult {
  blocked: boolean;
  secretTypes: SecretType[];
}

// a bare "-----BEGIN PRIVATE KEY-----" is a PEM parser constant; a leaked key
// carries its base64 body (newlines may arrive JSON-escaped as "\n")
const PEM_BODY = String.raw`(?:\s|\\[rn]|(?:Proc-Type|DEK-Info|Comment):[^\n]*)+[A-Za-z0-9+/=]{40,}`;

const KNOWN_SECRET_PATTERNS: ReadonlyArray<{
  type: SecretType;
  pattern: RegExp;
}> = [
  {
    type: "anthropic_api_key",
    pattern: /\bsk-ant-(?:api\d{2}-)?[A-Za-z0-9_-]{16,}\b/,
  },
  {
    type: "openai_api_key",
    pattern: /\bsk-(?!ant-)(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}\b/,
  },
  {
    type: "github_pat",
    pattern: /\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_\w{20,})\b/,
  },
  {
    type: "aws_access_key",
    pattern: /\b(?:AKIA|ASIA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[A-Z0-9]{16}\b/,
  },
  {
    type: "ssh_private_key",
    pattern: new RegExp(`-----BEGIN (?:OPENSSH PRIVATE KEY|SSH2 ENCRYPTED PRIVATE KEY)-----${PEM_BODY}`),
  },
  {
    type: "private_key",
    pattern: new RegExp(`-----BEGIN (?:RSA |EC |DSA |PKCS8 |ENCRYPTED )?PRIVATE KEY-----${PEM_BODY}`),
  },
];

const SENSITIVE_KEYS = new Set([
  "password",
  "passwd",
  "pwd",
  "token",
  "accesstoken",
  "authtoken",
  "refreshtoken",
  "apikey",
  "secret",
  "clientsecret",
  "signingsecret",
]);

const INLINE_ASSIGNMENTS = [
  // the optional quote after the key covers JSON: "client_secret": "..."
  /\b([\w-]+)["']?[ \t]*[:=][ \t]*"([^"\n]+)"/dgi,
  /\b([\w-]+)["']?[ \t]*[:=][ \t]*'([^'\n]+)'/dgi,
  // unquoted values only count on config-style lines (.env, YAML, INI, shell
  // export): in source code an unquoted right-hand side is always an expression
  /^[ \t]*(?:-[ \t]+)?(?:export[ \t]+)?([\w-]+)[ \t]*[:=][ \t]*([^\s"'`]+)[ \t]*(?:#.*)?$/dgim,
];

// "my token: <pasted value>" in chat: unquoted and mid-line, so only long
// letter+digit values count there
const PROSE_ASSIGNMENT = /\b([\w-]+)[ \t]*[:=][ \t]*([A-Za-z0-9_\-+/=.~]{16,})(?=[\s.,;)]|$)/dgi;

const PLACEHOLDER_VALUES = new Set([
  "example", "sample", "test", "dummy", "placeholder", "redacted", "masked",
  "changeme", "password", "secret", "token", "api_key", "api-key", "none",
  "null", "undefined", "bansos",
]);

const PLACEHOLDER_WORDS = new Set([
  "example", "sample", "test", "testing", "dummy", "fake", "mock", "stub",
  "fixture", "demo", "placeholder", "redacted", "masked", "hidden", "changeme",
  "invalid", "expired", "your", "lorem",
  // doc/sample passwords spell the word out: "SecurePassword123!", "MySecret1"
  "password", "passwd", "secret",
]);

function isPlaceholderValue(value: string): boolean {
  const lower = value.toLowerCase();
  if (PLACEHOLDER_VALUES.has(lower)) return true;
  if (/^[x*•.]+$/i.test(value)) return true;
  // truncated UI/doc samples: "LZhriF9bf88pPyk..."
  if (/(?:\.\.\.|…)$/.test(value)) return true;
  // "mock-jwt-token", "test_refresh_token", "***REDACTED***", "password123"
  const words = value.split(/[^A-Za-z]+|(?<=[a-z])(?=[A-Z])/).filter(Boolean).map((w) => w.toLowerCase());
  return words.some((word) => PLACEHOLDER_WORDS.has(word));
}

// Judges the value itself, never the key name: auth code is full of
// token/password/secret keys whose values are types, variables or messages.
function isLikelyCredentialValue(value: string): boolean {
  const clean = value.trim().replace(/^["']|["']$/g, "");
  if (clean.length < 8 || isPlaceholderValue(clean)) return false;
  // a secret is one opaque token: whitespace means prose or an error message,
  // and brackets, commas, pipes or semicolons mean code, generics or rules
  if (/[\s()[\]{}<>`,;|\\]/.test(clean)) return false;
  // paths, URLs and variable references point at a secret, they don't hold one
  if (/^(?:\.{0,2}\/|~\/|[a-z][a-z\d+.-]*:\/\/|[$%@])/i.test(clean)) return false;
  // digit-free identifiers ("accessToken", "JWT_SECRET", "cursorAuth/accessToken") are names
  if (!/\d/.test(clean) && /^[A-Za-z_$][\w$.?/:-]*$/.test(clean)) return false;
  // member chains with a plain-word segment ("tokenType_js_1.default.COMMA");
  // JWT segments are long base64 and essentially never digit-free words
  const segments = clean.split(".");
  if (segments.length > 1 && segments.every((s) => /^[A-Za-z_$][\w$]*$/.test(s))
    && segments.some((s) => /^[A-Za-z_$]{1,32}$/.test(s))) return false;
  return true;
}

interface SecretSpan {
  start: number;
  end: number;
  type: SecretType;
}

const GLOBAL_SECRET_PATTERNS = KNOWN_SECRET_PATTERNS.map(({ type, pattern }) => ({
  type,
  pattern: new RegExp(pattern.source, "g"),
}));

// a PEM match only covers the header and first body chunk; redaction has to
// swallow the rest of the base64 body too, up to the END line when present
function pemSpanEnd(value: string, matchEnd: number): number {
  const endMarker = /-----END [A-Z0-9 ]+-----/g;
  endMarker.lastIndex = matchEnd;
  const end = endMarker.exec(value);
  if (end) return end.index + end[0].length;
  const rest = /^(?:\s|\\[rn]|[A-Za-z0-9+/=])*/.exec(value.slice(matchEnd));
  return matchEnd + (rest?.[0].length ?? 0);
}

function findSecretSpans(value: string): SecretSpan[] {
  const spans: SecretSpan[] = [];

  for (const { type, pattern } of GLOBAL_SECRET_PATTERNS) {
    pattern.lastIndex = 0;
    for (let match = pattern.exec(value); match; match = pattern.exec(value)) {
      // vendor doc samples such as AKIAIOSFODNN7EXAMPLE
      if (isPlaceholderValue(match[0])) continue;
      const matchEnd = match.index + match[0].length;
      const end = type === "private_key" || type === "ssh_private_key" ? pemSpanEnd(value, matchEnd) : matchEnd;
      spans.push({ start: match.index, end, type });
    }
  }

  for (const pattern of INLINE_ASSIGNMENTS) {
    pattern.lastIndex = 0;
    for (let match = pattern.exec(value); match; match = pattern.exec(value)) {
      const key = match[1] ?? "";
      const assigned = match[2] ?? "";
      const range = match.indices?.[2];
      if (range && SENSITIVE_KEYS.has(normalizeKey(key)) && isLikelyCredentialValue(assigned)) {
        spans.push({ start: range[0], end: range[1], type: "credential_assignment" });
      }
    }
  }

  PROSE_ASSIGNMENT.lastIndex = 0;
  for (let match = PROSE_ASSIGNMENT.exec(value); match; match = PROSE_ASSIGNMENT.exec(value)) {
    const assigned = match[2] ?? "";
    const range = match.indices?.[2];
    if (
      range &&
      SENSITIVE_KEYS.has(normalizeKey(match[1] ?? "")) &&
      /[A-Za-z]/.test(assigned) &&
      /\d/.test(assigned) &&
      isLikelyCredentialValue(assigned)
    ) {
      spans.push({ start: range[0], end: range[1], type: "credential_assignment" });
    }
  }

  return spans;
}

function redactString(value: string, spans: SecretSpan[]): string {
  const sorted = [...spans].sort((a, b) => a.start - b.start || b.end - a.end);
  let out = "";
  let cursor = 0;
  for (const span of sorted) {
    // overlapping detections (a key inside an assignment) collapse into the first
    if (span.end <= cursor) continue;
    out += value.slice(cursor, Math.max(cursor, span.start));
    out += `[REDACTED:${span.type}]`;
    cursor = span.end;
  }
  return out + value.slice(cursor);
}

function normalizeKey(key: string): string {
  return key.toLowerCase().replace(/[^a-z0-9]/g, "");
}

function isSensitiveEntry(key: string | undefined, value: string): boolean {
  return !!key && SENSITIVE_KEYS.has(normalizeKey(key)) && isLikelyCredentialValue(value);
}

function inspectValue(
  value: unknown,
  found: Set<SecretType>,
  seen: WeakSet<object>,
  key?: string,
): void {
  if (typeof value === "string") {
    for (const span of findSecretSpans(value)) found.add(span.type);
    if (isSensitiveEntry(key, value)) found.add("credential_assignment");
    return;
  }

  if (!value || typeof value !== "object") return;
  if (seen.has(value)) return;
  seen.add(value);

  if (Array.isArray(value)) {
    for (const item of value) inspectValue(item, found, seen);
    return;
  }

  for (const [childKey, childValue] of Object.entries(value)) {
    inspectValue(childValue, found, seen, childKey);
  }
}

function redactValue(value: unknown, found: Set<SecretType>, key?: string): unknown {
  if (typeof value === "string") {
    if (isSensitiveEntry(key, value)) {
      found.add("credential_assignment");
      return "[REDACTED:credential_assignment]";
    }
    const spans = findSecretSpans(value);
    if (spans.length === 0) return value;
    for (const span of spans) found.add(span.type);
    return redactString(value, spans);
  }

  if (Array.isArray(value)) return value.map((item) => redactValue(item, found));
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.entries(value).map(([childKey, childValue]) => [childKey, redactValue(childValue, found, childKey)]),
  );
}

export function scanRequestBody(body: unknown): SecretScanResult {
  let parsed = body;
  if (typeof body === "string") {
    try {
      parsed = JSON.parse(body) as unknown;
    } catch {
      parsed = body;
    }
  }

  const found = new Set<SecretType>();
  inspectValue(parsed, found, new WeakSet<object>());
  const secretTypes = [...found].sort((a, b) => a.localeCompare(b));
  return { blocked: secretTypes.length > 0, secretTypes };
}

export interface SecretRedactResult {
  body: string;
  secretTypes: SecretType[];
}

// Replaces every detected secret in a serialized request body with a
// "[REDACTED:<type>]" marker, so the request can still go out without the
// value. Blocking instead would wedge an agent session for good: the secret
// sits in the conversation history and every later turn resends it.
export function redactRequestBody(body: string): SecretRedactResult {
  const found = new Set<SecretType>();
  let redacted: string;
  try {
    redacted = JSON.stringify(redactValue(JSON.parse(body) as unknown, found));
  } catch {
    redacted = redactValue(body, found) as string;
  }
  const secretTypes = [...found].sort((a, b) => a.localeCompare(b));
  return { body: secretTypes.length > 0 ? redacted : body, secretTypes };
}
