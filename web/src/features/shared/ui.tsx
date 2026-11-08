import type { ReactNode } from "react";
export function Field({
  name,
  children,
}: {
  name: string;
  children: ReactNode;
}) {
  return (
    <div>
      <dt>{name}</dt>
      <dd>{children ?? "—"}</dd>
    </div>
  );
}
export function TextData({ value }: { value: unknown }) {
  return (
    <pre className="evidence" tabIndex={0} aria-label="상세 데이터">
      {value == null ? "정보 없음" : JSON.stringify(value, null, 2)}
    </pre>
  );
}
export function Pages({
  next,
  previous,
  onNext,
  onPrevious,
}: {
  next: string;
  previous: boolean;
  onNext: () => void;
  onPrevious: () => void;
}) {
  return (
    <div className="pagination">
      <span>페이지 단위 조회</span>
      <div>
        <button disabled={!previous} onClick={onPrevious}>
          이전
        </button>
        <button disabled={!next} onClick={onNext}>
          다음
        </button>
      </div>
    </div>
  );
}
export const ipHref = (ip: string) => `/ips/${encodeURIComponent(ip)}`;
export const reportHref = (id: string) => `/reports/${encodeURIComponent(id)}`;
function record(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}
function ipNumber(raw: unknown): { family: number; value: bigint } | null {
  if (typeof raw !== "string") return null;
  if (/^\d+\.\d+\.\d+\.\d+$/.test(raw)) {
    const bytes = raw.split(".");
    if (bytes.some((b) => Number(b) > 255 || (b.length > 1 && b[0] === "0")))
      return null;
    return {
      family: 4,
      value: bytes.reduce((n, b) => n * 256n + BigInt(b), 0n),
    };
  }
  try {
    const url = new URL(`http://[${raw}]/`);
    const host = url.hostname.slice(1, -1);
    if (!host.includes(":")) return null;
    const parts = host.split("::"),
      left = parts[0] ? parts[0].split(":") : [],
      right = parts[1] ? parts[1].split(":") : [];
    const groups =
      parts.length === 2
        ? [
            ...left,
            ...Array(8 - left.length - right.length).fill("0"),
            ...right,
          ]
        : left;
    if (groups.length !== 8) return null;
    return {
      family: 6,
      value: groups.reduce((n, b) => n * 65536n + BigInt(`0x${b}`), 0n),
    };
  } catch {
    return null;
  }
}
export function contactCandidates(value: unknown, sourceIP: string): string[] {
  if (
    !record(value) ||
    value.address !== sourceIP ||
    value.lookup_succeeded !== true ||
    !Array.isArray(value.candidates)
  )
    return [];
  const ip = ipNumber(sourceIP);
  if (!ip) return [];
  return [
    ...new Set(
      value.candidates.flatMap((item: unknown) => {
        if (
          !record(item) ||
          typeof item.email !== "string" ||
          item.email.length > 254 ||
          !/^[^\s@<>()\[\]:;,\\"]+@[^\s@<>()\[\]:;,\\"]+$/.test(item.email) ||
          item.role !== "abuse" ||
          !Array.isArray(item.sources)
        )
          return [];
        const verified = item.sources.some((source: unknown) => {
          if (
            !record(source) ||
            source.role !== "abuse" ||
            (source.method !== "rdap" && source.method !== "whois") ||
            typeof source.source_url !== "string" ||
            !source.source_url
          )
            return false;
          const start = ipNumber(source.network_start),
            end = ipNumber(source.network_end);
          return (
            start &&
            end &&
            start.family === ip.family &&
            end.family === ip.family &&
            start.value <= ip.value &&
            end.value >= ip.value
          );
        });
        return verified ? [item.email] : [];
      }),
    ),
  ];
}
