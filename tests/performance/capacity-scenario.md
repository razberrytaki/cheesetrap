# Finite-horizon capacity calculation example

This example uses three isolated lifecycle measurements on the ARM64 reference host from 2026-10-22.
It does not guarantee storage capacity, retention duration, or supported events per second (EPS), and it does not define minimum requirements.

```sh
python3 scripts/storage-capacity.py tests/performance/capacity-scenario.json
```

## Input distribution and verification scope

Assume one daily burst of 1,000 web events over about 50 seconds.
One report for one source then contains 1,000 evidence items, 981 rules, and 3 revisions.
There is no input at other times, and bursts are separated by more than the 10-minute detection window.
The measurements inserted normalized rows into an isolated DB. They used synthetic GET requests across 6 repeated paths,
private source addresses, `is_test=true`, and historical timestamps.
They did not measure sensor transport costs or a uniform input of 1,000 events per day.

Mapping the fixture's 51-second report window to one report in the default UTC daily window is a scenario assumption.
The probe replaced one detection's evidence with exact legacy links to verify reads of mixed formats.
It preserved SQL and job timeouts, and detection and protection semantics.
The probe called the actual detection, sealing, draft, and revision functions.
It did not measure storage costs for normal River jobs, public IP lookups, SMTP, or HTTP concurrency.
A separate large report from 36,000 mixed inputs failed at the 30-second SQL timeout. This example does not represent that report's costs.

## Cost calculation without double counting

Each relation's `pg_total_relation_size` includes the heap, indexes, and TOAST.
Do not add JSON text size, TOAST, or indexes again.
The initial empty DB was 10,122,931 bytes. Actual DB growth through the evidence copies and 3 revisions was 11,943,936 bytes.
The sum of relation growth, 11,796,480 bytes, plus the remaining allocation, 147,456 bytes, matches that growth exactly.

Calculate per-row cost by rounding up the first cycle's physical growth divided by its row count.
Use the maximum fan-out observed across the three cycles for daily row counts.
These values are not proven maxima for other chunk orderings or inputs.
Do not treat 0 or small growth from page reuse in later cycles as free storage.

| JSON component | Rows per day | Bytes per row | First physical growth / row count |
|---|---:|---:|---:|
| events | 1,000 | 795 | 794,624 / 1,000 |
| detection_completions | 1,000 | 254 | 253,952 / 1,000 |
| detection_results | 981 | 1,387 | 1,359,872 / 981 |
| detection_evidence | 1 | 24,576 | 24,576 / 1 |
| detection_evidence_chunks | 5,204 | 148 | 647,168 / 4,396 |
| evidence_chunk_members | 45,684 | 141 | 6,430,720 / 45,684 |
| evidence_chunks | 981 | 385 | 376,832 / 981 |
| protected_report_evidence | 1,000 | 844 | 843,776 / 1,000 |
| protected_initial_report_revision | 1 | 344,064 | 344,064 / 1 |
| protected_additional_report_revisions | 2 | 274,432 | 548,864 / 2 |

Reference counts were 4,396, 5,204, and 5,012. Member event counts were 45,684, 44,292, and 43,732.
The remaining daily budgets in bytes are 40,960 for reports, 16,384 for candidates, 32,768 for windows,
16,384 for window completions, 40,960 for file generations, 24,576 for sensors, and 147,456 for other allocations.
These budgets assume the first physical page allocation repeats daily. They are not general marginal costs per metadata row.
The fixture creates a new sensor and file generation each cycle. A fixed production sensor need not do so.
If you deduct this difference, do not omit other unmeasured metadata.

The model's daily DB growth is **12,079,960 bytes**.
Count evidence copies once per event and count each immutable revision's full evidence and rule snapshot separately.
The model assumes no deadline for reports to reach a terminal state, so report-related components have `retention_days` set to null.
It also assumes no expiry for windows, completions, generations, sensors, or other allocations.
Event and detection components specify eligibility after 30 days and a nominal deletion capacity of 144,000 rows per day.
The final size calculation **deducts nothing for deletions**.

The 144,000 rows per day is a simple calculation based on one normal run per minute and at most 100 rows per statement.
Dependencies, locks, protection, interruptions, and failures reduce actual deletion capacity.
Input below that rate does not prove a steady state. The DB size after VACUUM also grew across the three cycles,
from 16.87 to 18.13 to 19.87 MB.

## Host, log, and recovery budgets

| Item | Value | Basis |
|---|---:|---|
| Reference filesystem | 50,884,108,288 bytes | Measured as 47.390 GiB |
| Other used space | 26 GiB | Explicit budget assumption, not a measurement of unrelated space usage alone |
| Source DB baseline | 10,122,931 bytes | Empty DB from the same fixture |
| Source PG WAL | 2 GiB | Budget for retained space, not cumulative WAL generation |
| Raw JSONL | 2 × 1 GiB + 64 MiB | Sensor caps plus assumed overflow between rotations or during interruptions |
| Auxiliary web logs | 10 MiB | Nominal rotation budget of 5 MiB × 2 |
| Compose diagnostic logs | 60 MiB | Assumes 6 retained containers × 5 MiB × 2 |
| Source DB working space | 25% of future DB size | Assumed temporary and allocation space, with no guarantee that it covers all unmeasured costs |
| Backup archive | 100% of future DB size | Assumes one local copy |
| Concurrent restore DB | 125% of future DB size | Assumes one separate target, including temporary space and index work during restore |
| Restore PG WAL | Separate 2 GiB | Separate cluster created by the restore tool |

`raw_reserve_bytes`, the sum of raw, auxiliary, and Compose logs, is **2,287,992,832 bytes**.
Do not add 7 days of unlimited raw logs to the sensor caps.
Timer interruptions, large records, or additional retained admin containers can increase the budget.
PG's `max_wal_size` is not a hard quota. This budget is neither a filesystem guarantee nor an upper bound for arbitrary attacks.

The actual small dump was 1,279,472 bytes, or 0.057982 times the source DB size.
The restored DB in the same cluster was 21,812,915 bytes, or 0.988492 times the source DB size.
These compression and restore ratios are not general upper bounds, so the example above uses different budgets.
The documented recovery procedure uses a separate cluster. Include its additional WAL.
The source DB still exists during restore.

## Results and interpretation at 180 days

Calculate with `G=12,079,960`, `H=180`, and `D(H)=10,122,931+G×H`.

```text
D(180) = 2,184,515,731 bytes
backup_reserve_bytes = ceil(2.25 × D(180)) + 2 GiB
                     = 7,062,644,043 bytes
planned total = other space + source WAL + raw/logs
              + 1.25 × D(180) + backup_reserve_bytes
              = 42,146,052,611 bytes (rounded up)
required filesystem at 80% = 52,682,565,764 bytes (49.064 GiB)
```

The reference disk of 47.390 GiB **does not meet this scenario's 80% budget**.
Planned headroom is −1,438,765,981 bytes.
This calculation models synthetic demand after 180 days and an assumed recovery budget.
It does not describe current usage, recommend a minimum disk size, or establish supported EPS.

`optimistic_live_row_bytes` is a logical lower bound that assumes all nominal cleanup succeeds. It is not a physical disk forecast.
`steady_state_proven` is false.
The output's `no_cleanup_days_to_warning` is not the number of operating days currently left.
It is an arithmetic result with backup and restore space already reserved at the DB size after 180 days.
Do not cite it as remaining operating time based on current usage.
If you change the horizon, input rate, or costs, recalculate `backup_reserve_bytes` for the future DB size.
Operational plans must account for actual usage, a separate copy for archive packaging, the restore method, additional services, and unmeasured costs.
