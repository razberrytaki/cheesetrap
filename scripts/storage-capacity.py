#!/usr/bin/env python3
"""Read-only finite-horizon storage model from operator-supplied measured costs.

No database connection or cleanup is performed. Each component must be disjoint:
count heap/index/TOAST once; model repeated revision snapshots separately from
one-time evidence copies. Deleted rows may remain physically allocated. The
optimistic live-row floor is NOT a physical disk forecast or capacity guarantee.
"""
import argparse
import json
import math
from pathlib import Path

_FIELDS = {'horizon_days', 'filesystem_bytes', 'other_used_bytes', 'database_base_bytes',
           'wal_reserve_bytes', 'backup_reserve_bytes', 'maintenance_fraction',
           'warning_fraction', 'raw_reserve_bytes', 'components'}
_COMPONENT = {'name', 'rows_per_day', 'bytes_per_row', 'retention_days', 'delete_rows_per_day'}


def number(value, *, positive=False):
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0 or (positive and value == 0):
        raise ValueError('finite nonnegative numeric input required')
    return value


def estimate(s):
    if not isinstance(s, dict) or set(s) != _FIELDS:
        raise ValueError('capacity fields must match schema')
    for key in _FIELDS - {'components'}:
        number(s[key], positive=key in {'horizon_days', 'filesystem_bytes', 'warning_fraction'})
    if s['warning_fraction'] >= 1 or not isinstance(s['components'], list) or not s['components']:
        raise ValueError('warning fraction below one and nonempty components required')
    days = s['horizon_days']
    names = set()
    components = []
    daily_bytes = 0
    floor_bytes = 0
    for c in s['components']:
        if not isinstance(c, dict) or set(c) != _COMPONENT:
            raise ValueError('component fields must match schema')
        name = c['name']
        if not isinstance(name, str) or not name.strip() or name in names:
            raise ValueError('unique nonempty component name required')
        names.add(name)
        rate = number(c['rows_per_day'])
        cost = number(c['bytes_per_row'])
        supply = number(c['delete_rows_per_day'])
        age = c['retention_days']
        if age is not None:
            number(age, positive=True)
        created = rate * days
        if age is None:
            floor = created
            backlog = 0
            status = 'no_expiry_bound'
        else:
            expired_days = max(0, days-age)
            backlog = max(0, rate-supply)*expired_days
            floor = rate*min(days, age)+backlog
            status = ('arrival_exceeds_nominal_supply' if rate > supply else
                      'no_recovery_margin' if rate == supply else 'nominal_supply_exceeds_arrivals')
        daily_bytes += rate*cost
        floor_bytes += floor*cost
        components.append(dict(name=name, rows_per_day=rate, delete_rows_per_day=supply,
                               no_cleanup_rows=math.ceil(created), optimistic_live_rows=math.ceil(floor),
                               expired_backlog_rows=math.ceil(backlog), drain_status=status,
                               net_backlog_rows_per_day=max(0, rate-supply) if age is not None else rate))
    no_cleanup = s['database_base_bytes'] + daily_bytes*days
    # A reserve for bloat/working space is explicit, not inferred from a short run.
    factor = 1+s['maintenance_fraction']
    fixed = s['other_used_bytes']+s['wal_reserve_bytes']+s['backup_reserve_bytes']+s['raw_reserve_bytes']
    total = fixed + no_cleanup*factor
    warning = s['filesystem_bytes']*s['warning_fraction']
    available = max(0, warning-fixed-s['database_base_bytes']*factor)
    runway = 0 if available == 0 else (available/(daily_bytes*factor) if daily_bytes else None)
    return dict(schema=1, basis='finite_horizon_planning_not_retention_guarantee',
                steady_state_proven=False, components=components,
                horizon_days=days, daily_database_growth_bytes=daily_bytes,
                optimistic_live_row_bytes=math.ceil(s['database_base_bytes']+floor_bytes),
                database_no_cleanup_bytes=math.ceil(no_cleanup),
                planned_no_cleanup_total_bytes=math.ceil(total),
                required_filesystem_bytes_at_warning=math.ceil(total/s['warning_fraction']),
                fits_no_cleanup_horizon=total <= warning, no_cleanup_days_to_warning=runway,
                limitations=['Costs and arrival/fanout rates are scenario assumptions, not universal upper bounds.',
                             'Nominal cleanup supply is optimistic: locks, dependencies, starvation, errors and downtime reduce it.',
                             'Protected or unexpired rows are not eligible for deletion; unresolved rows need a separate no-expiry component.',
                             'Normal VACUUM reuses space and need not return it to the filesystem.',
                             'WAL generation is not WAL retained bytes; reserve actual retained WAL separately.',
                             'Backup/restore, raw-log overshoot and non-expiring metadata require explicit reserves or components.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('scenario', type=Path, help='explicit measured-cost JSON; see tests/performance/capacity-scenario.md')
    args = parser.parse_args()
    try:
        result = estimate(json.loads(args.scenario.read_text()))
    except (ValueError, TypeError, KeyError, OSError, OverflowError):
        parser.exit(2, 'invalid capacity scenario\n')
    print(json.dumps(result, indent=2, allow_nan=False))


if __name__ == '__main__':
    main()
