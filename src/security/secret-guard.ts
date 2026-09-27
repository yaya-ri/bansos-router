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
  /\b([\w-]+)["']?[ \t]*[:=][ \t]*"([^"\n]+)"/gi,
  /\b([\w-]+)["']?[ \t]*[:=][ \t]*'([^'\n]+)'/gi,
  // unquoted values only count on config-style lines (.env, YAML, INI, shell
  // export): in source code an unquoted right-hand side is always an expression
  /^[ \t]*(?:-[ \t]+)?(?:export[ \t]+)?([\w-]+)[ \t]*[:=][ \t]*([^\s"'`]+)[ \t]*(?:#.*)?$/gim,
];

// "my token: <pasted value>" in chat: unquoted and mid-line, so only long
// letter+digit values count there
const PROSE_ASSIGNMENT = /\b([\w-]+)[ \t]*[:=][ \t]*([A-Za-z0-9_\-+/=.~]{16,})(?=[\s.,;)]|$)/gi;

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

function inspectString(value: string, found: Set<SecretType>): void {
  for (const { type, pattern } of KNOWN_SECRET_PATTERNS) {
    // vendor doc samples such as AKIAIOSFODNN7EXAMPLE
    const match = pattern.exec(value);
    if (match && !isPlaceholderValue(match[0])) found.add(type);
  }

  for (const pattern of INLINE_ASSIGNMENTS) {
    pattern.lastIndex = 0;
    for (let match = pattern.exec(value); match; match = pattern.exec(value)) {
      const key = match[1] ?? "";
      const assigned = match[2] ?? "";
      if (SENSITIVE_KEYS.has(normalizeKey(key)) && isLikelyCredentialValue(assigned)) {
        found.add("credential_assignment");
      }
    }
  }

  PROSE_ASSIGNMENT.lastIndex = 0;
  for (let match = PROSE_ASSIGNMENT.exec(value); match; match = PROSE_ASSIGNMENT.exec(value)) {
    const assigned = match[2] ?? "";
    if (
      SENSITIVE_KEYS.has(normalizeKey(match[1] ?? "")) &&
      /[A-Za-z]/.test(assigned) &&
      /\d/.test(assigned) &&
      isLikelyCredentialValue(assigned)
    ) {
      found.add("credential_assignment");
    }
  }
}

function normalizeKey(key: string): string {
  return key.toLowerCase().replace(/[^a-z0-9]/g, "");
}

function inspectValue(
  value: unknown,
  found: Set<SecretType>,
  seen: WeakSet<object>,
  key?: string,
): void {
  if (typeof value === "string") {
    inspectString(value, found);
    if (key && SENSITIVE_KEYS.has(normalizeKey(key)) && isLikelyCredentialValue(value)) {
      found.add("credential_assignment");
    }
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
