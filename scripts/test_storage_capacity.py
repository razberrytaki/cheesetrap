"""Capacity is a planning model, never a guarantee that retention will keep up."""
import copy
import importlib.util
import math
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('storage_capacity', Path(__file__).with_name('storage-capacity.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def scenario():
    return dict(horizon_days=30, filesystem_bytes=1000000, other_used_bytes=100,
                database_base_bytes=1000, wal_reserve_bytes=100,
                backup_reserve_bytes=100, maintenance_fraction=.25,
                warning_fraction=.8, raw_reserve_bytes=100,
                components=[dict(name='events', rows_per_day=100, bytes_per_row=10,
                                 retention_days=7, delete_rows_per_day=200)])


class CapacityTests(unittest.TestCase):
    def test_sufficient_cleanup_is_only_optimistic_floor(self):
        r = m.estimate(scenario())
        self.assertEqual(r['components'][0]['optimistic_live_rows'], 700)
        self.assertEqual(r['components'][0]['no_cleanup_rows'], 3000)
        self.assertFalse(r['steady_state_proven'])
        self.assertEqual(r['components'][0]['drain_status'], 'nominal_supply_exceeds_arrivals')
        self.assertEqual(r['database_no_cleanup_bytes'], 31000)
        self.assertEqual(r['planned_no_cleanup_total_bytes'], 39150)
        self.assertAlmostEqual(r['no_cleanup_days_to_warning'], (800000-100-100-100-100-1250)/1250)

    def test_cleanup_deficit_preserves_expired_backlog(self):
        s = scenario();s['components'][0]['delete_rows_per_day'] = 50
        r = m.estimate(s)['components'][0]
        self.assertEqual(r['optimistic_live_rows'], 1850) # 3000 - 50*(30-7)
        self.assertEqual(r['expired_backlog_rows'], 1150)
        self.assertEqual(r['drain_status'], 'arrival_exceeds_nominal_supply')
        self.assertEqual(r['net_backlog_rows_per_day'], 50)

    def test_shorter_days_cannot_make_deficit_stable(self):
        s = scenario();s['components'][0].update(retention_days=1, delete_rows_per_day=50)
        self.assertEqual(m.estimate(s)['components'][0]['drain_status'], 'arrival_exceeds_nominal_supply')

    def test_protected_and_metadata_rows_have_no_finite_retention(self):
        s = scenario();s['components'].append(dict(name='unresolved_copies',rows_per_day=10,bytes_per_row=20,retention_days=None,delete_rows_per_day=0))
        c=m.estimate(s)['components'][1]
        self.assertEqual(c['optimistic_live_rows'],300)
        self.assertEqual(c['drain_status'],'no_expiry_bound')
        self.assertFalse(m.estimate(s)['steady_state_proven'])

    def test_equal_supply_has_no_recovery_margin(self):
        s=scenario();s['components'][0]['delete_rows_per_day']=100
        self.assertEqual(m.estimate(s)['components'][0]['drain_status'],'no_recovery_margin')

    def test_no_cleanup_projection_does_not_depend_on_deletion_optimism(self):
        s=scenario();a=m.estimate(s)
        s['components'][0]['delete_rows_per_day']=0
        b=m.estimate(s)
        self.assertEqual(a['database_no_cleanup_bytes'], b['database_no_cleanup_bytes'])
        self.assertEqual(a['planned_no_cleanup_total_bytes'], b['planned_no_cleanup_total_bytes'])

    def test_existing_usage_above_warning_has_zero_runway(self):
        s=scenario();s['other_used_bytes']=900000
        r=m.estimate(s)
        self.assertEqual(r['no_cleanup_days_to_warning'],0)
        self.assertFalse(r['fits_no_cleanup_horizon'])

    def test_zero_growth_runway_distinguishes_safe_and_exhausted_budget(self):
        s=scenario();s['components'][0]['rows_per_day']=0
        self.assertIsNone(m.estimate(s)['no_cleanup_days_to_warning'])
        for used in (798450, 900000):
            s['other_used_bytes']=used
            self.assertEqual(m.estimate(s)['no_cleanup_days_to_warning'],0)

    def test_reject_unknown_duplicate_negative_nonfinite_and_bool_values(self):
        for key, value in [('horizon_days',0),('wal_reserve_bytes',-1),('maintenance_fraction',-1),('warning_fraction',1),('filesystem_bytes',float('nan')),('backup_reserve_bytes',True)]:
            s=scenario();s[key]=value
            with self.subTest(key=key), self.assertRaises(ValueError):m.estimate(s)
        for field,value in [('rows_per_day',float('inf')),('bytes_per_row',-1),('retention_days',0),('delete_rows_per_day',True)]:
            s=scenario();s['components'][0][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):m.estimate(s)
        s=scenario();s['components'].append(copy.deepcopy(s['components'][0]))
        with self.assertRaises(ValueError):m.estimate(s)
        s=scenario();s['typo']=1
        with self.assertRaises(ValueError):m.estimate(s)

if __name__=='__main__': unittest.main()
