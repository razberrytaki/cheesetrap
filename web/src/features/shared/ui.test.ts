import { describe, it, expect } from "vitest";
import { contactCandidates } from "./ui";
const source = {
  role: "abuse",
  method: "rdap",
  source_url: "https://rdap.example.net/ip/192.0.2.10",
  network_start: "192.0.2.0",
  network_end: "192.0.2.255",
};
const registry = {
  address: "192.0.2.10",
  lookup_succeeded: true,
  candidates: [
    { email: "abuse@example.net", role: "abuse", sources: [source] },
  ],
};
describe("verified registry candidates", () => {
  it("only enables abuse mailboxes with lookup and matching source provenance", () => {
    expect(contactCandidates(registry, "192.0.2.10")).toEqual([
      "abuse@example.net",
    ]);
    expect(
      contactCandidates({ ...registry, lookup_succeeded: false }, "192.0.2.10"),
    ).toEqual([]);
    expect(contactCandidates(registry, "192.0.2.11")).toEqual([]);
    for (const candidate of [
      { email: "Name <a@example.net>", role: "abuse", sources: [source] },
      { email: "a@example.net", role: "technical", sources: [source] },
      { email: "a@example.net", role: "abuse", sources: [] },
      {
        email: "a@example.net",
        role: "abuse",
        sources: [{ ...source, network_start: "192.0.3.0" }],
      },
    ])
      expect(
        contactCandidates(
          { ...registry, candidates: [candidate] },
          "192.0.2.10",
        ),
      ).toEqual([]);
  });
  it("narrows hostile or malformed registry values safely", () => {
    for (const value of [
      null,
      5,
      "hello",
      [],
      { candidates: [null, 5, { email: [] }] },
    ])
      expect(contactCandidates(value, "192.0.2.10")).toEqual([]);
  });
  it("supports IPv6 range provenance without numeric precision loss", () => {
    expect(
      contactCandidates(
        {
          ...registry,
          address: "2001:db8::10",
          candidates: [
            {
              email: "v6@example.net",
              role: "abuse",
              sources: [
                {
                  ...source,
                  network_start: "2001:db8::",
                  network_end: "2001:db8::ffff",
                },
              ],
            },
          ],
        },
        "2001:db8::10",
      ),
    ).toEqual(["v6@example.net"]);
  });
});
