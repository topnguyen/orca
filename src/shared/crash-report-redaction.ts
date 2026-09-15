import type {
  CrashReportBreadcrumb,
  CrashReportBreadcrumbInput,
  CrashReportDetailValue
} from './crash-reporting'

const MAX_STRING_DETAIL_LENGTH = 240
const MAX_STACK_DETAIL_LENGTH = 4_000
const MAX_BREADCRUMB_NAME_LENGTH = 80
const MAX_BREADCRUMBS = 30

const SECRET_PATTERNS = [
  /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/g,
  /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g,
  /\bglpat-[A-Za-z0-9_-]{20,}\b/g,
  /\bsk-[A-Za-z0-9_-]{20,}\b/g,
  /\bxox[baprs]-[A-Za-z0-9-]{10,}/g,
  /\bAKIA[0-9A-Z]{16}\b/g,
  /\bBearer\s+[A-Za-z0-9._~+/-]{20,}/gi,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g
]
const CREDENTIAL_URL_PATTERN = /\b[A-Za-z0-9._%+-]+:[A-Za-z0-9._%+-]+@(?=[^/\s]+)/g
const SECRET_ASSIGNMENT_PATTERN =
  /\b(token|access[_-]?token|refresh[_-]?token|api[_-]?key|client[_-]?secret|secret|password|account[_-]?key)\s*[:=]\s*(?:"[^"\r\n]*"|'[^'\r\n]*'|[^&\s,;]+)/gi

/**
 * Build-asset stack-frame tails, preserved where whole-path redaction would take them.
 *
 * A minified frame is only clusterable by its asset name and offset, and for a BUILD ASSET
 * both are build output: identical for every install of a release, carrying nothing about the
 * machine. The directory in front of them identifies a user, so that is the part replaced.
 *
 * Why the asset must carry a content hash, and not merely end in `.js`: "ends in .js with an
 * offset" is a property no user file is prevented from having, so gating on it preserved the
 * basename of anything — `bob-divorce-settlement.js:3:9` included. The gate is therefore the
 * bundler's own output shape: a final `-` segment of exactly 8 base64url characters holding at
 * least one digit, underscore, or capital. Measured against every asset name appearing in a
 * field stack (153 distinct), that keeps 152 and drops only the unhashed `index.js`; measured
 * against document-shaped names it keeps none. A frame that does not match stays fully redacted.
 *
 * Why the `:line:col` is required as well: it is what separates a frame from a filename in
 * prose, and a frame with no offset cannot be clustered on anyway.
 *
 * Why only `file:` and bare paths anchor it: allowing any `scheme://` let the rule eat the host
 * of an `http(s)://…/app-HASH.js:1:2` frame and mangle `webpack://` and `chrome-extension://`
 * module paths, which are themselves the triage axis for those frames and carry no machine
 * identity. `.` joins `:` and the separators in the lookbehind for the same reason — without it
 * a `webpack://orca/./src/…` frame anchors on the slash after the dot.
 *
 * Runs before PATH_PATTERNS, which redact a frame whole and did so asymmetrically:
 * `file:///C:/…` starts its path after the drive colon, which the unquoted-Windows rule matches,
 * while `file:///Users/…` starts its at the scheme's third slash, which the unquoted-POSIX rule's
 * lookbehind rejects. Windows frames lost their offsets; POSIX frames kept the user's home
 * directory. One rule, so neither.
 *
 * Case-sensitive on purpose: the capital in the hash gate is load-bearing.
 */
const STACK_FRAME_PATH_PATTERN =
  /(?:file:\/\/(?=[\\/])|(?<![A-Za-z0-9:.\\/])(?:[A-Za-z]:)?)[\\/][^\s"'`<>)]*?[\\/]([A-Za-z0-9._-]*-(?=[A-Za-z0-9_-]{8}\.[cm]?js)(?=[A-Za-z0-9_-]*[A-Z0-9_])[A-Za-z0-9_-]{8}\.[cm]?js)(:\d+:\d+)/g

// Quoted paths retain spaces; unquoted paths stop at whitespace to preserve prose.
const PATH_PATTERNS = [
  // A file:// URL, whatever follows the scheme. The unquoted rules below cannot
  // see one: `file:///Users/…` puts a slash before the path's own leading
  // slash, which rule 5's lookbehind rejects, so POSIX file URLs were reaching
  // submitted reports unredacted. Quoted first, so a URL holding spaces is
  // taken whole rather than truncated at the first one.
  /(["'`])file:\/\/(?:(?!\1)[^<>\n\r])+\1/gi,
  /\bfile:\/\/\/?(?:[A-Za-z]:)?[\\/][^\s"'`<>)]*/gi,
  /(["'`])\/[A-Za-z0-9._-]+\/(?:(?!\1)[^<>\n\r])+\1/g,
  /(["'`])[A-Za-z]:\\(?:(?!\1)[^<>\n\r])+\1/gi,
  /(["'`])\\\\[^\\\s"'`<>\n\r)]+\\(?:(?!\1)[^<>\n\r])+\1/gi,
  /(?<![A-Za-z0-9./])\/[A-Za-z0-9._-]+\/(?:\\ |[^\s"'`<>)]*)/g,
  /(?<![A-Za-z0-9])[A-Za-z]:\\(?:\\ |[^\s"'`<>\n\r)]*)/gi,
  /\\\\[^\\\s"'`<>\n\r)]+\\(?:\\ |[^\s"'`<>\n\r)]*)/gi,
  /%(?:USERPROFILE|APPDATA|LOCALAPPDATA|HOMEDRIVE|HOMEPATH)%[^\s"'`<>)]*/gi
]

export function sanitizeCrashReportString(
  value: string,
  maxLength = MAX_STRING_DETAIL_LENGTH
): string {
  let sanitized = value.replace(
    STACK_FRAME_PATH_PATTERN,
    (_match, asset: string, offset: string) => `[redacted-path]/${asset}${offset}`
  )
  for (const pattern of PATH_PATTERNS) {
    sanitized = sanitized.replace(pattern, '[redacted-path]')
  }
  sanitized = sanitized.replace(CREDENTIAL_URL_PATTERN, '[redacted-credential]@')
  sanitized = sanitized.replace(SECRET_ASSIGNMENT_PATTERN, (_match, key: string) => {
    return `${key}=[redacted]`
  })
  for (const pattern of SECRET_PATTERNS) {
    sanitized = sanitized.replace(pattern, '[redacted-secret]')
  }
  return sanitized.length > maxLength ? `${sanitized.slice(0, maxLength)}...` : sanitized
}

export function sanitizeCrashReportDetails(
  details: Record<string, unknown>
): Record<string, CrashReportDetailValue> {
  const sanitized: Record<string, CrashReportDetailValue> = {}
  for (const [key, value] of Object.entries(details)) {
    if (typeof value === 'string') {
      const normalizedKey = key.replace(/([a-z0-9])([A-Z])/g, '$1_$2')
      if (/(?:^|_)path$/i.test(normalizedKey)) {
        sanitized[key] = '[redacted-path]'
      } else {
        const maxLength =
          /(?:^|_)(?:stack|component_stack|error_stack|minidump_check_message)$/i.test(
            normalizedKey
          )
            ? MAX_STACK_DETAIL_LENGTH
            : MAX_STRING_DETAIL_LENGTH
        sanitized[key] = sanitizeCrashReportString(value, maxLength)
      }
    } else if (typeof value === 'number' && Number.isFinite(value)) {
      sanitized[key] = value
    } else if (typeof value === 'boolean' || value === null) {
      sanitized[key] = value
    }
  }
  return sanitized
}

export function sanitizeCrashReportBreadcrumbs(
  breadcrumbs: CrashReportBreadcrumbInput[] | undefined
): CrashReportBreadcrumb[] | undefined {
  if (!breadcrumbs || breadcrumbs.length === 0) {
    return undefined
  }

  const sanitized = breadcrumbs
    .slice(-MAX_BREADCRUMBS)
    .map((breadcrumb): CrashReportBreadcrumb | null => {
      if (!breadcrumb.name.trim() || !breadcrumb.createdAt.trim()) {
        return null
      }
      const data = breadcrumb.data ? sanitizeCrashReportDetails(breadcrumb.data) : {}
      const origin = breadcrumb.origin
        ? sanitizeCrashReportString(breadcrumb.origin).slice(0, 80)
        : ''
      return {
        createdAt: sanitizeCrashReportString(breadcrumb.createdAt),
        name: sanitizeCrashReportString(breadcrumb.name).slice(0, MAX_BREADCRUMB_NAME_LENGTH),
        ...(Object.keys(data).length > 0 ? { data } : {}),
        ...(origin ? { origin } : {})
      }
    })
    .filter((breadcrumb): breadcrumb is CrashReportBreadcrumb => breadcrumb !== null)

  return sanitized.length > 0 ? sanitized : undefined
}
