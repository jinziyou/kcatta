import * as React from "react"

const MOBILE_BREAKPOINT = 768

const query = `(max-width: ${MOBILE_BREAKPOINT - 1}px)`

/**
 * Tracks whether the viewport is below the mobile breakpoint.
 *
 * The initial value is read lazily via `useSyncExternalStore`'s snapshot rather
 * than set synchronously inside an effect — the latter triggers the cascading
 * re-render that `react-hooks/set-state-in-effect` flags. SSR falls back to
 * `false` (desktop-first) until hydration.
 */
export function useIsMobile() {
  const subscribe = React.useCallback((onChange: () => void) => {
    const mql = window.matchMedia(query)
    mql.addEventListener("change", onChange)
    return () => mql.removeEventListener("change", onChange)
  }, [])

  return React.useSyncExternalStore(
    subscribe,
    () => window.innerWidth < MOBILE_BREAKPOINT,
    () => false,
  )
}
