/**
 * Cold-park verdict telemetry and a safe-side circuit breaker.
 * Field breadcrumbs prove render-cadence flips, but not which eligibility input
 * oscillates; damping keeps the pane mounted rather than let it cycle.
 *
 * Two horizons, because churn harms in two ways: a burst reaches React's commit
 * bail (#185), while churn merely sustained remounts the pane over and over.
 * A remount does not reconnect a terminal — parking deliberately keeps the PTY
 * alive (see terminal-parked-tab-watchers), SSH restores from main's snapshot,
 * and a remote runtime re-subscribes a stream on a per-environment multiplexer
 * that outlives the pane. What it costs is a remount each time, indefinitely.
 * Both horizons engage the same unpark pin.
 *
 * What this is NOT: a fix for whatever keeps re-proposing the park. That input
 * is still unidentified, so this caps the remount rate of an oscillation rather
 * than ending it — the pin masks the rendered verdict, and the driver resumes
 * the moment each pin lapses.
 *
 * Scope: flips are counted on the rendered verdict and the pin subtracts from
 * that same verdict (selectParkVerdictPinnedTabIds), so churn driven by any
 * parked input — worktree-level park, portal ownership, deferred activation
 * mounts — is damped, not only the cold-park candidate set. A repeating `burst`
 * crumb for one tab therefore means the driver keeps re-proposing the park once
 * each pin lapses, not that damping never reached it.
 */
import { recordRendererCrashBreadcrumb } from '@/lib/crash-breadcrumb-recorder'
import { REACT_NESTED_UPDATE_LIMIT } from '../../../../shared/react-update-depth-attribution'

export const TERMINAL_TAB_PARK_FLIP_WINDOW_MS = 60_000
/** Flips per window that no sane park policy should reach. */
export const TERMINAL_TAB_PARK_FLIP_NOTICE_LIMIT = 12
/**
 * Ceiling for the sustained-churn pin. Each consecutive notice-limit window
 * doubles the pin, so a verdict that cannot settle is re-proposed on the order
 * of minutes instead of every ~45s; a tab quiet for one full window restarts at 1x.
 *
 * Only the notice path backs off. A burst still takes a flat one-window pin,
 * which the corpus supports: repeat bursts arrive a median 732s apart, and only
 * 1 of 30 inter-arrivals falls in the 59-75s band that would mean a burst
 * re-firing the instant its pin lapsed.
 */
export const TERMINAL_TAB_PARK_FLIP_SUSTAINED_PIN_MAX_MS = 8 * TERMINAL_TAB_PARK_FLIP_WINDOW_MS

/** Measured upper bound after the passive-effect pin engages. */
const PARK_PIN_SETTLE_COMMITS = 6
/** Worst-case commits from pane, watcher, and store work per verdict flip. */
export const TERMINAL_TAB_PARK_FLIP_COMMIT_COST = 12
/** Pin threshold derived from React's remaining commit budget. */
export const TERMINAL_TAB_PARK_FLIP_BURST_LIMIT = Math.max(
  2,
  Math.floor(
    (REACT_NESTED_UPDATE_LIMIT - PARK_PIN_SETTLE_COMMITS) / TERMINAL_TAB_PARK_FLIP_COMMIT_COST
  )
)
/** Honest cold parking cannot round-trip inside this horizon. */
export const TERMINAL_TAB_PARK_FLIP_BURST_WINDOW_MS = 1_000

export type ParkVerdictFlipRecord = {
  parked: boolean
  windowStartMs: number
  flips: number
  notified: boolean
  burstStartMs: number
  burstFlips: number
  /** Set when flip churn engaged damping; the verdict stays unparked until then. */
  pinnedUntilMs?: number | null
  /** Consecutive notice-limit windows; backs the pin off for churn that persists. */
  sustainedPinCount?: number
}

// Why it leaves pinnedUntilMs alone: the notice window is 60s from the first
// flip, so it lapses mid-pin; clearing here would release damping early.
function resetFlipWindows(record: ParkVerdictFlipRecord, nowMs: number): void {
  record.windowStartMs = nowMs
  record.flips = 0
  record.notified = false
  record.burstStartMs = nowMs
  record.burstFlips = 0
}

// Why liveness and not presence: a tab pinned while cold-park-eligible can stop
// being a candidate before its deadline, and nothing would consult it again. An
// expired pin must stop damping and stop gating breadcrumbs on its own.
function isParkVerdictPinLive(record: ParkVerdictFlipRecord, nowMs: number): boolean {
  return record.pinnedUntilMs != null && nowMs < record.pinnedUntilMs
}

/** Returns the safe-side pin deadline and re-arms an expired window. */
export function getParkVerdictUnparkPinUntilMs(args: {
  records: Map<string, ParkVerdictFlipRecord>
  tabId: string
  nowMs: number
}): number | null {
  const record = args.records.get(args.tabId)
  if (record?.pinnedUntilMs == null) {
    return null
  }
  if (!isParkVerdictPinLive(record, args.nowMs) || args.nowMs < record.windowStartMs) {
    resetFlipWindows(record, args.nowMs)
    record.pinnedUntilMs = null
    return null
  }
  return record.pinnedUntilMs
}

/** Records park-verdict churn per tab; damps bursts and breadcrumbs the rest. */
export function recordParkVerdictFlips(args: {
  records: Map<string, ParkVerdictFlipRecord>
  liveTabIds: ReadonlySet<string>
  nextParkedTabIds: ReadonlySet<string>
  nowMs: number
  flipWindowMs?: number
  noticeLimit?: number
  burstWindowMs?: number
  burstLimit?: number
  sustainedPinMaxMs?: number
}): void {
  const {
    records,
    liveTabIds,
    nextParkedTabIds,
    nowMs,
    flipWindowMs = TERMINAL_TAB_PARK_FLIP_WINDOW_MS,
    noticeLimit = TERMINAL_TAB_PARK_FLIP_NOTICE_LIMIT,
    burstWindowMs = TERMINAL_TAB_PARK_FLIP_BURST_WINDOW_MS,
    burstLimit = TERMINAL_TAB_PARK_FLIP_BURST_LIMIT,
    sustainedPinMaxMs = TERMINAL_TAB_PARK_FLIP_SUSTAINED_PIN_MAX_MS
  } = args

  for (const tabId of Array.from(records.keys())) {
    if (!liveTabIds.has(tabId)) {
      records.delete(tabId)
    }
  }

  for (const tabId of liveTabIds) {
    const parked = nextParkedTabIds.has(tabId)
    const record = records.get(tabId)

    if (!record) {
      records.set(tabId, {
        parked,
        windowStartMs: nowMs,
        flips: 0,
        notified: false,
        burstStartMs: nowMs,
        burstFlips: 0,
        pinnedUntilMs: null
      })
      continue
    }
    if (parked === record.parked) {
      // Why the back-off clears here and not only on a flip: churn stopping
      // looks like no flips at all, so a flip-gated reset would ratchet — a tab
      // that churned once at launch would still carry a ceiling pin hours on.
      //
      // Why quiet is measured from the pin deadline and not from windowStartMs:
      // while a tab is pinned the hook subtracts it from the rendered verdict,
      // so no flip is recorded and windowStartMs never advances. By the time a
      // pin lapses, windowStartMs is at least a notice window plus a pin old —
      // always past flipWindowMs — so measuring from it reset the count on the
      // first pass after EVERY pin, and the back-off could never reach 2x. The
      // deadline is still readable here because the selector nulls the pin one
      // statement later, in the same effect pass.
      const quietSinceMs = Math.max(record.windowStartMs, record.pinnedUntilMs ?? 0)
      if (
        record.sustainedPinCount &&
        !isParkVerdictPinLive(record, nowMs) &&
        nowMs - quietSinceMs >= flipWindowMs
      ) {
        record.sustainedPinCount = 0
      }
      continue
    }

    // Why: Date.now() jumps backwards on NTP/sleep-wake; treat any out-of-range
    // elapsed value as a fresh window rather than trusting the delta.
    const elapsedMs = nowMs - record.windowStartMs
    if (elapsedMs >= flipWindowMs || elapsedMs < 0) {
      // Why here and not in resetFlipWindows: a window that closed below the
      // notice limit is the only proof the churn actually stopped. The reset on
      // pin lapse must NOT clear the count, or the back-off can never grow.
      if (record.flips < noticeLimit) {
        record.sustainedPinCount = 0
      }
      resetFlipWindows(record, nowMs)
    }
    const burstElapsedMs = nowMs - record.burstStartMs
    if (burstElapsedMs >= burstWindowMs || burstElapsedMs < 0) {
      record.burstStartMs = nowMs
      record.burstFlips = 0
    }

    record.parked = parked
    record.flips += 1
    record.burstFlips += 1

    if (!isParkVerdictPinLive(record, nowMs) && record.burstFlips >= burstLimit) {
      record.pinnedUntilMs = nowMs + flipWindowMs
      recordRendererCrashBreadcrumb('terminal_park_verdict_churn', {
        tabId,
        trigger: 'burst',
        flips: record.burstFlips,
        elapsedMs: nowMs - record.burstStartMs,
        windowMs: burstWindowMs,
        pinnedForMs: flipWindowMs
      })
      continue
    }
    // Why a live pin gates this: the burst crumb already reported the same
    // window, so a second crumb would only double the volume the notice limit
    // exists to keep down.
    if (!isParkVerdictPinLive(record, nowMs) && !record.notified && record.flips >= noticeLimit) {
      record.notified = true
      // Why this pins too: the burst window only catches churn fast enough to
      // reach React's commit bail. Churn one flip every ~3-5s never bursts, so
      // it used to run unbounded — 47min in one field launch, 9min in another.
      // Each remount is user-visible, so the notice limit damps on its own.
      const sustainedPinCount = (record.sustainedPinCount ?? 0) + 1
      record.sustainedPinCount = sustainedPinCount
      const pinnedForMs = Math.min(flipWindowMs * 2 ** (sustainedPinCount - 1), sustainedPinMaxMs)
      record.pinnedUntilMs = nowMs + pinnedForMs
      // Why: flips is always exactly noticeLimit here, so elapsedMs is the only
      // field that separates slow churn from a burst the damping already caught.
      recordRendererCrashBreadcrumb('terminal_park_verdict_churn', {
        tabId,
        trigger: 'window',
        flips: record.flips,
        elapsedMs: nowMs - record.windowStartMs,
        windowMs: flipWindowMs,
        pinnedForMs,
        sustainedPinCount
      })
    }
  }
}

export type ParkVerdictPinSelection = {
  pinnedTabIds: Set<string>
  /** Earliest live pin deadline, so a caller can wake exactly when damping lapses. */
  earliestPinExpiryMs: number | null
}

/**
 * Tab ids a flip burst pinned unparked, expiring lapsed pins in place.
 *
 * Why every live tab and not only cold-park candidates: flips are counted on
 * the rendered verdict, so the oscillating input can be one the cold-park
 * selector never sees (worktree-level park, activation-deferred mounts). A pin
 * consulted only through the cold set then damps nothing and never lapses —
 * it just silences its own breadcrumb for the window and re-arms forever.
 */
export function selectParkVerdictPinnedTabIds(args: {
  records: Map<string, ParkVerdictFlipRecord>
  tabIds: Iterable<string>
  nowMs: number
}): ParkVerdictPinSelection {
  const pinnedTabIds = new Set<string>()
  let earliestPinExpiryMs: number | null = null
  for (const tabId of args.tabIds) {
    const pinnedUntilMs = getParkVerdictUnparkPinUntilMs({
      records: args.records,
      tabId,
      nowMs: args.nowMs
    })
    if (pinnedUntilMs === null) {
      continue
    }
    pinnedTabIds.add(tabId)
    earliestPinExpiryMs =
      earliestPinExpiryMs === null ? pinnedUntilMs : Math.min(earliestPinExpiryMs, pinnedUntilMs)
  }
  return { pinnedTabIds, earliestPinExpiryMs }
}
