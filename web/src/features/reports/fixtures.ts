import type { components } from "../../api/schema";
export const reportID = "00000000-0000-4000-8000-000000000002";
export const revisionID = "00000000-0000-4000-8000-000000000003";
export const refresh = {
  created_at: "",
  completed_at: null,
  current_revision_id: "",
  expected_version: "",
  request_id: "",
  result_revision_id: null,
  status: "",
};
export const revision: components["schemas"]["RevisionView"] = {
  report_id: reportID,
  revision_id: revisionID,
  version: "9007199254740993",
  source_ip: "192.0.2.10",
  recipient: "",
  reply_to: "ops@example.org",
  subject: "<img src=x onerror=alert(1)>",
  body: "<script>attack()</script>",
  body_edited: false,
  content_digest: "sha256:synthetic",
  created_at: "2026-10-18T00:00:00Z",
  delayed_collection: true,
  evidence_count: "1",
  rule_count: "1",
  hold_reasons: ["contact_ambiguous"],
  state: "held",
  observed_start: "2026-10-17T00:00:00Z",
  observed_end: "2026-10-17T01:00:00Z",
  window_start: "2026-10-18T00:00:00Z",
  window_end: "2026-10-19T00:00:00Z",
  window_id: "window",
  registry_truncated: false,
  registry: {
    address: "192.0.2.10",
    lookup_succeeded: true,
    queried_at: "2026-10-18T00:00:00Z",
    expires_at: "2099-01-01T00:00:00Z",
    candidates: [
      {
        email: "abuse@example.net",
        role: "abuse",
        sources: [
          {
            role: "abuse",
            method: "rdap",
            source_url: "https://rdap.example.net/ip/192.0.2.10",
            network_start: "192.0.2.0",
            network_end: "192.0.2.255",
          },
        ],
      },
      {
        email: "security@example.net",
        role: "abuse",
        sources: [
          {
            role: "abuse",
            method: "rdap",
            source_url: "https://rdap.example.net/ip/192.0.2.10",
            network_start: "192.0.2.0",
            network_end: "192.0.2.255",
          },
        ],
      },
    ],
  },
};
export const report: components["schemas"]["ReportDetailOutputBody"] = {
  ...revision,
  current_revision_id: revisionID,
  latest_refresh: refresh,
  revision,
};
