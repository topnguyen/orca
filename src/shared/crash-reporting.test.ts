import { describe, expect, it } from 'vitest'
import {
  formatCrashReportText,
  formatUncapturedCrashReportText,
  isCrashReportReason,
  MAX_USER_NOTES_LENGTH,
  sanitizeCrashReportBreadcrumbs,
  sanitizeCrashReportDetails,
  sanitizeCrashReportString,
  type CrashReportRecord
} from './crash-reporting'

function notesReport(overrides: Partial<CrashReportRecord> = {}): CrashReportRecord {
  return {
    id: 'crash-notes',
    createdAt: '2026-08-16T01:00:00.000Z',
    status: 'pending',
    source: 'renderer',
    processType: 'renderer',
    reason: 'crashed',
    exitCode: 5,
    appVersion: '1.4.184',
    platform: 'win32',
    osRelease: '10.0.26200',
    arch: 'x64',
    electronVersion: '41.0.0',
    chromeVersion: '141.0.0',
    details: {},
    breadcrumbs: [],
    ...overrides
  }
}

/** Notes are emitted indented inside the fence; mirror that when asserting. */
function indentNote(note: string): string {
  return note
    .split('\n')
    .map((line) => `  ${line}`)
    .join('\n')
}

describe('crash-reporting shared helpers', () => {
  it('redacts paths and common secret-shaped strings', () => {
    const text =
      'file "/Users/alice/My Project/.env" /tmp/build log "C:\\Users\\bob\\My Project" token=abc123 ghp_abcdefghijklmnopqrstuvwxyz'

    expect(sanitizeCrashReportString(text)).toBe(
      'file [redacted-path] [redacted-path] log [redacted-path] token=[redacted] [redacted-secret]'
    )
  })

  it('redacts credential URLs and secret assignments without hiding their labels', () => {
    const value = 'https://alice:hunter2@example.com client_secret: "secret with spaces"'

    expect(sanitizeCrashReportString(value)).toBe(
      'https://[redacted-credential]@example.com client_secret=[redacted]'
    )
  })

  it('keeps details on a strict primitive allowlist', () => {
    const longStack = [
      'Error: boom',
      ...Array.from(
        { length: 200 },
        (_, index) => `at Component${index} (/Users/alice/project/src/file-${index}.tsx:1:1)`
      )
    ].join('\n')

    expect(
      sanitizeCrashReportDetails({
        name: 'GPU /home/alice/repo',
        code: 9,
        crashed: true,
        missing: null,
        error_stack: longStack,
        minidumpPath: '/Users/alice/Library/Application Support/Orca/reports/abc.dmp',
        nested: { nope: true },
        infinite: Number.POSITIVE_INFINITY
      })
    ).toEqual({
      name: 'GPU [redacted-path]',
      code: 9,
      crashed: true,
      missing: null,
      error_stack: expect.stringContaining('[redacted-path]'),
      minidumpPath: '[redacted-path]'
    })
    expect(
      String(sanitizeCrashReportDetails({ error_stack: longStack }).error_stack).length
    ).toBeGreaterThan(240)
    expect(String(sanitizeCrashReportDetails({ errorStack: longStack }).errorStack).length).toBe(
      4_003
    )
    expect(
      String(sanitizeCrashReportDetails({ componentStack: longStack }).componentStack).length
    ).toBe(4_003)
    expect(String(sanitizeCrashReportDetails({ description: longStack }).description).length).toBe(
      243
    )
  })

  it('preserves the failing CHECK at the end of a long fatal line', () => {
    const fatalLine = `[FATAL:node.cc(123)] ${'context '.repeat(80)}Check failed: !is_detached_.`

    const sanitized = String(
      sanitizeCrashReportDetails({ minidumpCheckMessage: fatalLine }).minidumpCheckMessage
    )

    expect(sanitized.length).toBeGreaterThan(240)
    expect(sanitized).toContain('Check failed: !is_detached_.')
  })

  it('sanitizes breadcrumb data and caps to the latest thirty entries', () => {
    const breadcrumbs = sanitizeCrashReportBreadcrumbs(
      Array.from({ length: 32 }, (_, index) => ({
        createdAt: `2026-05-16T01:${String(index).padStart(2, '0')}:00.000Z`,
        name: `event_${index}`,
        origin: 'renderer:42',
        data: {
          path: '/Users/alice/project',
          ok: true,
          nested: { ignored: true }
        }
      }))
    )

    expect(breadcrumbs).toHaveLength(30)
    expect(breadcrumbs?.[0].name).toBe('event_2')
    expect(breadcrumbs?.[0]).toMatchObject({
      origin: 'renderer:42',
      data: {
        path: '[redacted-path]',
        ok: true
      }
    })
  })

  it('recognizes crash reasons captured by Electron process-gone events', () => {
    expect(isCrashReportReason('abnormal-exit')).toBe(true)
    expect(isCrashReportReason('crashed')).toBe(true)
    expect(isCrashReportReason('launch-failed')).toBe(true)
    expect(isCrashReportReason('memory-eviction')).toBe(true)
    expect(isCrashReportReason('clean-exit')).toBe(false)
  })

  it('formats reports without route or URL fields', () => {
    const report: CrashReportRecord = {
      id: 'crash-1',
      createdAt: '2026-05-16T01:00:00.000Z',
      status: 'pending',
      source: 'renderer',
      processType: 'renderer',
      reason: 'crashed',
      exitCode: 5,
      appVersion: '1.0.0',
      platform: 'darwin',
      osRelease: '25.0.0',
      arch: 'arm64',
      electronVersion: '41.0.0',
      chromeVersion: '141.0.0',
      details: { reason: 'native crash' },
      breadcrumbs: [
        {
          createdAt: '2026-05-16T00:59:30.000Z',
          name: 'agent_state_changed',
          data: { agentType: 'codex', state: 'working' }
        }
      ]
    }

    const text = formatCrashReportText(report, 'saw /Users/me/project', {
      status: 'uploaded',
      ticketId: 'ticketabcdefghijklmnop',
      bundleSubmissionId: 'bundleabcdefghijklmnop',
      bytes: 1024,
      spanCount: 12
    })

    expect(text).toContain('[Crash Report]')
    expect(text).toContain('Recent activity:')
    expect(text).toContain('agent_state_changed')
    expect(text).toContain('Diagnostic log:')
    expect(text).toContain('ticketabcdefghijklmnop')
    expect(text.indexOf('Diagnostic log:')).toBeLessThan(text.indexOf('Details:'))
    expect(text).toContain('User notes:')
    expect(text).toContain('[redacted-path]')
    expect(text).not.toContain('Route:')
    expect(text).not.toContain('\nURL:')
  })

  it('names the failing CHECK above the details block', () => {
    const fatalLine =
      '[8104:1234:0815/143022.123456:FATAL:render_frame_impl.cc(4821)] Check failed: !is_detached_.'
    const report: CrashReportRecord = {
      id: 'crash-check',
      createdAt: '2026-08-15T01:00:00.000Z',
      status: 'pending',
      source: 'renderer',
      processType: 'renderer',
      reason: 'crashed',
      // The bare STATUS_BREAKPOINT this ticket is about.
      exitCode: -2147483645,
      appVersion: '1.4.183',
      platform: 'win32',
      osRelease: '10.0.19045',
      arch: 'x64',
      electronVersion: '43.1.0',
      chromeVersion: '150.0.7871.47',
      details: {
        minidumpCheckMessage: fatalLine,
        minidumpFaultingModule: 'chrome_elf.dll',
        minidumpFaultingModuleOffset: '0x1234'
      },
      breadcrumbs: []
    }

    const text = formatCrashReportText(report)

    // Why: Chromium logs the source basename, not a path, so the fatal line has
    // to survive path redaction intact or the check is unnameable again.
    expect(text).toContain(`Check failure: ${fatalLine}`)
    expect(text).toContain('Faulting module: chrome_elf.dll+0x1234')
    expect(text.indexOf('Check failure:')).toBeLessThan(text.indexOf('Details:'))
  })

  it('decodes POSIX wait statuses in the exit code line and leaves Windows codes raw', () => {
    const report = (overrides: Partial<CrashReportRecord>): CrashReportRecord => ({
      id: 'crash-wait-status',
      createdAt: '2026-08-14T09:32:19.696Z',
      status: 'pending',
      source: 'renderer',
      processType: 'renderer',
      reason: 'killed',
      exitCode: null,
      appVersion: '1.4.182',
      platform: 'linux',
      osRelease: '7.0.0-28-generic',
      arch: 'x64',
      electronVersion: '43.1.0',
      chromeVersion: '150.0.7871.47',
      details: {},
      ...overrides
    })

    // Field bundles: linux 61696 = exit(241), 9 = SIGKILL, 133 = SIGTRAP+core, darwin 5 = SIGTRAP.
    expect(formatCrashReportText(report({ exitCode: 61696 }))).toContain(
      'Exit code: 61696 (exit status 241)'
    )
    expect(formatCrashReportText(report({ exitCode: 9 }))).toContain('Exit code: 9 (SIGKILL)')
    expect(formatCrashReportText(report({ reason: 'crashed', exitCode: 133 }))).toContain(
      'Exit code: 133 (SIGTRAP, core dumped)'
    )
    expect(
      formatCrashReportText(report({ platform: 'darwin', reason: 'crashed', exitCode: 5 }))
    ).toContain('Exit code: 5 (SIGTRAP)')
    // Windows codes are not wait statuses; they must render byte-identical to before.
    expect(formatCrashReportText(report({ platform: 'win32', exitCode: 1 }))).toContain(
      'Exit code: 1\n'
    )
    expect(
      formatCrashReportText(report({ platform: 'win32', reason: 'oom', exitCode: -536870904 }))
    ).toContain('Exit code: -536870904\n')
    // launch-failed carries a Chromium launch error, not a wait status — never decode it.
    expect(formatCrashReportText(report({ reason: 'launch-failed', exitCode: 18 }))).toContain(
      'Exit code: 18\n'
    )
    // A clean exit(0) must not grow an "(exit status 0)" suffix.
    expect(formatCrashReportText(report({ reason: 'crashed', exitCode: 0 }))).toContain(
      'Exit code: 0\n'
    )
    expect(formatCrashReportText(report({}))).toContain('Exit code: unknown')
  })

  it('caps formatted reports to the crash endpoint limit', () => {
    const report: CrashReportRecord = {
      id: 'crash-oversized',
      createdAt: '2026-05-16T01:00:00.000Z',
      status: 'pending',
      source: 'renderer',
      processType: 'renderer',
      reason: 'crashed',
      exitCode: 5,
      appVersion: '1.0.0',
      platform: 'darwin',
      osRelease: '25.0.0',
      arch: 'arm64',
      electronVersion: '41.0.0',
      chromeVersion: '141.0.0',
      details: Object.fromEntries(
        Array.from({ length: 400 }, (_, index) => [`detail_${index}`, 'x'.repeat(240)])
      ),
      breadcrumbs: []
    }

    const text = formatCrashReportText(report)

    expect(text.length).toBeLessThanOrEqual(64_000)
    expect(text).toContain('[Crash report truncated to fit feedback endpoint limits.]')
  })

  it('formats uncaptured crash reports so users can still submit from Help', () => {
    const text = formatUncapturedCrashReportText(
      {
        createdAt: '2026-05-16T01:00:00.000Z',
        appVersion: '1.0.0',
        platform: 'darwin',
        osRelease: '25.0.0',
        arch: 'arm64',
        electronVersion: '41.0.0',
        chromeVersion: '141.0.0'
      },
      'happened after opening /Users/me/project',
      {
        status: 'not_uploaded',
        reason: 'diagnostic upload endpoint is not configured for this build',
        bundleSubmissionId: 'bundleabcdefghijklmnop',
        bytes: 2048,
        spanCount: 3
      }
    )

    expect(text).toContain('Report ID: not captured')
    expect(text).toContain('Reason: no captured crash report')
    expect(text).toContain('Diagnostic log:')
    expect(text).toContain('Status: not uploaded')
    expect(text).toContain('[redacted-path]')
  })

  it('keeps a user note longer than the 240-char detail cap intact', () => {
    // A real 1.4.184 note was cut mid-word by the telemetry detail budget.
    const note =
      `My phone is connected. ${'The Claude terminal never came back. '.repeat(20)}`.trim()

    const text = formatCrashReportText(notesReport(), note)

    expect(note.length).toBeGreaterThan(240)
    expect(text).toContain(`--- begin user notes ---\n${indentNote(note)}\n--- end user notes ---`)
    expect(text).not.toContain('...')
  })

  it('still redacts paths and secrets far past the old 240-char cap', () => {
    const note = [
      'a'.repeat(1_000),
      'it broke at /Users/alice/secret-project',
      'my token was ghp_abcdefghijklmnopqrstuvwxyz',
      'b'.repeat(1_000)
    ].join('\n')

    const text = formatCrashReportText(notesReport(), note)

    expect(text).toContain('it broke at [redacted-path]')
    expect(text).toContain('my token was [redacted-secret]')
    expect(text).not.toContain('alice')
    expect(text).not.toContain('ghp_abcdefghijklmnopqrstuvwxyz')
  })

  it('bounds an oversized user note to the advertised limit', () => {
    const text = formatCrashReportText(notesReport(), 'z'.repeat(40_000))
    const expected = `${'z'.repeat(MAX_USER_NOTES_LENGTH - 3)}...`

    expect(text).toContain(expected)
    expect(text).not.toContain('z'.repeat(MAX_USER_NOTES_LENGTH - 2))
  })

  it('keeps user notes when the report is truncated to the endpoint cap', () => {
    // Tail truncation must remove reproducible machine data before user notes.
    const text = formatCrashReportText(
      notesReport({
        details: Object.fromEntries(
          Array.from({ length: 400 }, (_, index) => [`detail_${index}`, 'x'.repeat(240)])
        )
      }),
      'the sidebar went blank'
    )

    expect(text.length).toBeLessThanOrEqual(64_000)
    expect(text).toContain('[Crash report truncated to fit feedback endpoint limits.]')
    expect(text).toContain('--- begin user notes ---\n  the sidebar went blank')
  })

  it('redacts path tokens without deleting surrounding prose', () => {
    const note = [
      'On 8/16/2026 the app froze right after I opened a worktree.',
      'Steps: open View/Layout then Window/Zoom and it crashes on run 3/4.',
      'The log is at /opt/orca/logs/app.log and the repo is /Users/alice/x but this survives.'
    ].join(' ')

    const text = formatCrashReportText(notesReport(), note)

    expect(text).toContain('On 8/16/2026 the app froze')
    expect(text).toContain('open View/Layout then Window/Zoom and it crashes on run 3/4.')
    expect(text).toContain(
      'The log is at [redacted-path] and the repo is [redacted-path] but this survives.'
    )
    expect(text).not.toContain('/opt/orca/logs/app.log')
    expect(text).not.toContain('alice')
  })

  it.each([
    ['POSIX', '/home/alice/orca/app.log then recovered.'],
    ['Windows', 'C:\\Users\\alice\\Orca\\app.log then recovered.'],
    ['UNC', '\\\\server\\share\\Orca\\app.log then recovered.']
  ])('stops unquoted %s paths at prose boundaries', (_platform, value) => {
    expect(sanitizeCrashReportString(value)).toBe('[redacted-path] then recovered.')
  })

  // Why these are asserted per platform rather than once: the generic path
  // rules treated them differently, and in opposite directions. `file:///C:/…`
  // begins its path after the drive colon, which the unquoted-Windows rule
  // matched, so Windows frames were redacted whole and lost the only thing a
  // minified stack can be clustered by. `file:///Users/…` and `file:///home/…`
  // begin theirs at the scheme's third slash, which the unquoted-POSIX rule's
  // lookbehind rejects, so those frames were not redacted at all and shipped
  // the user's home directory. Field evidence for both: of 19 React #185
  // payloads collected from the field, all 4 minified win32 stacks arrived with
  // every offset destroyed while all 13 darwin/linux stacks kept theirs — and
  // two payloads carried a real account name, one of them 48 times.
  it.each([
    [
      'darwin',
      'at _i (file:///Users/alice/Applications/Orca.app/Contents/Resources/app.asar/out/renderer/assets/Terminal-CHo8p2a1.js:1:7269)'
    ],
    [
      'linux',
      'at _i (file:///home/alice/.local/share/orca/resources/app.asar/out/renderer/assets/Terminal-CHo8p2a1.js:1:7269)'
    ],
    [
      'win32 URL',
      'at _i (file:///C:/Users/alice/AppData/Local/Programs/orca/resources/app.asar/out/renderer/assets/Terminal-CHo8p2a1.js:1:7269)'
    ],
    [
      'win32 backslash',
      'at _i (C:\\Users\\alice\\AppData\\Local\\Programs\\orca\\out\\renderer\\assets\\Terminal-CHo8p2a1.js:1:7269)'
    ]
  ])('keeps the asset and offset of a %s stack frame and drops the directory', (_p, frame) => {
    const sanitized = sanitizeCrashReportString(frame, 4_000)

    expect(sanitized).toBe('at _i ([redacted-path]/Terminal-CHo8p2a1.js:1:7269)')
    expect(sanitized).not.toContain('alice')
  })

  // Why every one of these carries a REAL offset: the offset is what arms the
  // rule, so a fixture without one asserts the safe behaviour of a code path
  // that never runs. Each case below is a file that ends in .js at a line and
  // column and must still be redacted whole, because only a bundler content
  // hash makes a basename safe to keep — "ends in .js" is a property no user
  // file is prevented from having.
  it.each([
    ['an unhashed entry point', 'at f (/Users/alice/app/index.js:1:2)', 'index.js'],
    ['a user document', 'crash at /Users/alice/Documents/bob-divorce-settlement.js:3:9', 'divorce'],
    [
      'a document naming a person',
      'crash at /Users/alice/Documents/alice.smith-acme-payroll-2025.js:1:1',
      'payroll'
    ],
    [
      'a project setup script',
      'at Object.x (/Users/alice/work/acme-gateway/.orca/setup.js:4:11)',
      'acme-gateway'
    ],
    ['a too-short hash-like tail', 'at f (/Users/alice/app/report-Q3-2025.js:1:2)', 'report-Q3'],
    [
      'an all-lowercase eight-letter tail',
      'at f (/Users/alice/app/client-invoices.js:1:2)',
      'invoices'
    ]
  ])('still redacts %s whole', (_case, value, marker) => {
    const sanitized = sanitizeCrashReportString(value, 4_000)

    expect(sanitized).not.toContain('alice')
    expect(sanitized).not.toContain(marker)
  })

  // Why a separate case: this hash holds dashes, which the gate's 8-character
  // base64url window must accept. It is a real asset name from the field corpus
  // and it is the shape a naive "last dash segment is alphanumeric" gate drops.
  it('keeps a hash that contains dashes', () => {
    const sanitized = sanitizeCrashReportString(
      'at _i (file:///Users/alice/orca/assets/client-creation-action-error-ihM-f-zg.js:1:7269)',
      4_000
    )

    expect(sanitized).toBe(
      'at _i ([redacted-path]/client-creation-action-error-ihM-f-zg.js:1:7269)'
    )
  })

  // Why: a frame with no offset has nothing to cluster on, so it stays whole.
  it('still redacts a hashed asset with no offset whole', () => {
    const sanitized = sanitizeCrashReportString(
      'at _i (file:///Users/alice/orca/out/renderer/assets/Terminal-CHo8p2a1.js)',
      4_000
    )

    expect(sanitized).not.toContain('alice')
    expect(sanitized).not.toContain('Terminal-CHo8p2a1.js')
  })

  // Why these are pinned: an earlier revision anchored on any `scheme://`, which
  // ate the host of an http frame and mangled module paths that are themselves
  // the triage axis for their loader and carry no machine identity.
  it.each([
    ['an http asset frame', 'at ai (https://localhost:5173/assets/app-CHo8p2a1.js:1:2)'],
    ['a webpack module', 'at f (webpack://orca/./src/components/Terminal-CHo8p2a1.js:10:5)'],
    ['an extension script', 'at f (chrome-extension://abcdefghijklmnop/content-CHo8p2a1.js:1:2)'],
    ['a relative frame', 'at f (./src/app.js:1:2)']
  ])('leaves %s untouched', (_case, value) => {
    expect(sanitizeCrashReportString(value, 4_000)).toBe(value)
  })

  // Why each of these is pinned: every one of them regressed while this rule
  // was being written. The drive-letter branch matched the `e:` inside `file:`
  // and ate half the scheme; the unquoted file:// rule truncated a quoted URL
  // at its first space and left the tail behind; and http(s) URLs and Node's
  // `node:internal/...` frames must not be touched at all.
  it.each([
    [
      // No directory means nothing to preserve a basename against, so this
      // falls through to whole-path redaction rather than being a special case.
      'a file URL with no directory',
      'file:///Terminal-CHo8p2a1.js:1:7269',
      '[redacted-path]'
    ],
    [
      'a quoted URL holding spaces',
      'opened "file:///Users/alice/My Docs/notes.log" ok',
      'opened [redacted-path] ok'
    ],
    [
      'a percent-encoded space',
      'opened file:///Users/alice/My%20Docs/notes.log ok',
      'opened [redacted-path] ok'
    ],
    [
      'a POSIX file URL in prose',
      'file:///home/alice/orca/x.log then recovered.',
      '[redacted-path] then recovered.'
    ],
    [
      'an http URL',
      'see https://react.dev/errors/185 for details',
      'see https://react.dev/errors/185 for details'
    ],
    [
      'a node internal frame',
      'at genericNodeError (node:internal/errors:986:15)',
      'at genericNodeError (node:internal/errors:986:15)'
    ],
    [
      'prose holding a colon',
      'the ratio was 3:4 and file: was empty',
      'the ratio was 3:4 and file: was empty'
    ]
  ])('handles %s', (_case, value, expected) => {
    expect(sanitizeCrashReportString(value, 4_000)).toBe(expected)
  })

  it('keeps every frame of a multi-frame minified stack clusterable', () => {
    const stack = [
      'Error: Minified React error #185; visit https://react.dev/errors/185',
      '    at _i (file:///C:/Users/alice/AppData/Local/orca/assets/client-CXJwj0PF.js:8:27510)',
      '    at mi (file:///C:/Users/alice/AppData/Local/orca/assets/client-CXJwj0PF.js:8:27083)',
      '    at Kc (file:///C:/Users/alice/AppData/Local/orca/assets/Terminal-CHo8p2a1.js:1:91686)'
    ].join('\n')

    const sanitized = sanitizeCrashReportString(stack, 4_000)

    expect(sanitized).toContain('client-CXJwj0PF.js:8:27510')
    expect(sanitized).toContain('client-CXJwj0PF.js:8:27083')
    expect(sanitized).toContain('Terminal-CHo8p2a1.js:1:91686')
    expect(sanitized).not.toContain('alice')
    expect(sanitized).not.toContain('AppData')
  })

  it('redacts the secret shapes a full-page notes box can now hold', () => {
    const note = [
      'pat github_pat_11AAAAAAA0abcdefghijklmnopqrstuvwxyz012345',
      // Assembling the fixture avoids GitHub push-protection false positives.
      `slack ${['xoxb', '0'.repeat(11), 'fixture', 'not-a-real-token'].join('-')}`,
      `gitlab ${['glpat', 'a'.repeat(24)].join('-')}`,
      'aws AKIAIOSFODNN7EXAMPLE',
      'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.body.sig',
      'authorization: bearer eyJhbGciOiJIUzI1NiJ9.lowercase.signature',
      'client_secret: "secret with spaces"',
      '-----BEGIN OPENSSH PRIVATE KEY-----',
      'b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAAB',
      '-----END OPENSSH PRIVATE KEY-----',
      'log at %USERPROFILE%\\Documents\\payroll.xlsx'
    ].join('\n')

    const text = formatCrashReportText(notesReport(), note)

    expect(text).not.toContain('github_pat_11AAAAAAA0')
    expect(text).not.toContain('not-a-real-token')
    expect(text).not.toContain('glpat-')
    expect(text).not.toContain('AKIAIOSFODNN7EXAMPLE')
    expect(text).not.toContain('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9')
    expect(text).not.toContain('eyJhbGciOiJIUzI1NiJ9.lowercase.signature')
    expect(text).not.toContain('secret with spaces')
    expect(text).toContain('client_secret=[redacted]')
    expect(text).not.toContain('b3BlbnNzaC1rZXktdjEA')
    expect(text).not.toContain('payroll.xlsx')
  })

  it('redacts an incomplete private-key paste', () => {
    const text = formatCrashReportText(
      notesReport(),
      '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA'
    )

    expect(text).not.toContain('b3BlbnNzaC1rZXktdjEAAAAA')
    expect(text).toContain('[redacted-secret]')
  })

  it('bounds sanitizer work on a padded paste instead of freezing the dialog', () => {
    // The raw-input clamp prevents path regexes from scanning an unbounded paste.
    const note = `/Users/a${' '.repeat(200_000)}end`
    const startedAt = Date.now()

    const text = formatCrashReportText(notesReport(), note)

    expect(Date.now() - startedAt).toBeLessThan(1_000)
    expect(text.length).toBeLessThan(64_000)
  })

  it('clamps raw notes before trimming', () => {
    const text = formatCrashReportText(
      notesReport(),
      `${' '.repeat(20_000)}content beyond the raw-input limit`
    )

    expect(text).not.toContain('content beyond the raw-input limit')
    expect(text).not.toContain('User notes:')
  })

  it('places Help-menu notes before machine-generated fields', () => {
    const text = formatUncapturedCrashReportText(
      {
        createdAt: '2026-05-16T01:00:00.000Z',
        appVersion: '1.0.0',
        platform: 'darwin',
        osRelease: '25.0.0',
        arch: 'arm64',
        electronVersion: '41.0.0',
        chromeVersion: '141.0.0'
      },
      'the terminal font looks wrong'
    )

    expect(text.startsWith('[Crash Report]')).toBe(true)
    expect(text).toContain('- captured_crash_report: false')
    expect(text).toContain('--- begin user notes ---\n  the terminal font looks wrong')
    expect(text.indexOf('--- begin user notes ---')).toBeLessThan(text.indexOf('Details:'))
  })
})

describe('user note section fencing', () => {
  it('stops a note from forging a machine-generated section', () => {
    const text = formatCrashReportText(
      notesReport({ details: { captured_crash_report: true } }),
      'here is what I saw\n\nDetails:\n- captured_crash_report: false'
    )
    // Only the generated Details heading may remain line-parser-visible.
    expect(text.match(/^Details:$/gm)).toHaveLength(1)
    expect(text).not.toMatch(/^- captured_crash_report: false$/m)
    expect(text).toContain('  Details:')
    expect(text).toContain('  - captured_crash_report: false')
    expect(text).toMatch(/^- captured_crash_report: true$/m)
  })
})
