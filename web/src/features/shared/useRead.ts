import { useEffect, useState } from "react";
import { errorMessage, isCancelled } from "../../api/client";
export type ReadState<T> =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; data: T };
// The caller supplies stable dependencies; cleanup prevents even non-abortable fetch mocks from winning a race.
export function useRead<T>(
  read: (signal: AbortSignal) => Promise<T>,
  deps: readonly unknown[],
) {
  const [state, setState] = useState<ReadState<T>>({ kind: "loading" });
  useEffect(() => {
    let active = true;
    const abort = new AbortController();
    setState({ kind: "loading" });
    read(abort.signal)
      .then((data) => {
        if (active) setState({ kind: "ready", data });
      })
      .catch((error: unknown) => {
        if (active && !isCancelled(error))
          setState({
            kind: "error",
            message: errorMessage(
              error,
              "정보를 불러오지 못했습니다. 다시 시도하세요.",
            ),
          });
      });
    return () => {
      active = false;
      abort.abort();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  return state;
}
