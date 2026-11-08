import { useEffect } from "react";

// Multiple mounted mutation panels may independently hold a navigation lock.
const tokens = new Set<symbol>();
export function navigationLocked(): boolean {
  return tokens.size > 0;
}

export function useNavigationLock(active: boolean): void {
  useEffect(() => {
    if (!active) return;
    const token = Symbol("pending-mutation");
    tokens.add(token);
    const preventUnload = (event: BeforeUnloadEvent) => {
      event.preventDefault();
      event.returnValue = "";
    };
    window.addEventListener("beforeunload", preventUnload);
    return () => {
      tokens.delete(token);
      window.removeEventListener("beforeunload", preventUnload);
    };
  }, [active]);
}
