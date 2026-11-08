import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('metrics', Path(__file__).with_name('performance-metrics.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class MetricsTests(unittest.TestCase):
    def test_reference_requires_native_arm64_and_bounded_machine(self):
        good = dict(os='Ubuntu', version='24.04', architecture='aarch64', cpus=4, memory_bytes=24*1024**3, disk_bytes=47.4*1024**3, emulated=False)
        self.assertTrue(m.reference_environment(good))
        for key, value in [('architecture','x86_64'), ('cpus',2), ('memory_bytes',4*1024**3), ('disk_bytes',40*1024**3), ('emulated',True), ('emulated',None)]:
            self.assertFalse(m.reference_environment(dict(good, **{key:value})))

    def test_percentile_nearest_rank_and_empty(self):
        self.assertEqual(m.percentile(list(range(1,101)), .95), 95)
        self.assertIsNone(m.percentile([], .95))

    def test_capacity_is_growth_projection_not_measured_retention(self):
        result = m.capacity_projection(1000, 6000, 1000, 20, 30)
        self.assertEqual(result['bytes_per_event'], 5)
        self.assertEqual(result['projected_bytes'], 5*20*86400*30)
        self.assertEqual(result['basis'], 'linear_projection_not_retention_measurement')
        self.assertIsNone(m.capacity_projection(0,6000,10,20,30))
        self.assertIsNone(m.capacity_projection(1000,500,1000,20,30))

    def test_api_window_excludes_warmup_and_drain(self):
        samples=[dict(api_at='2026-10-21T00:00:%02d+00:00'%i,api_milliseconds=value,api_error=False) for i,value in [(0,9000),(1,12),(2,14),(3,9000)]]
        result=m.api_window(samples,'2026-10-21T00:00:01Z','2026-10-21T00:00:02Z')
        self.assertEqual(result,dict(samples=2,errors=0,p95_milliseconds=14))
        samples[1]['api_error']=True
        self.assertEqual(m.api_window(samples,'2026-10-21T00:00:01Z','2026-10-21T00:00:02Z')['errors'],1)

    def test_runtime_requires_owned_test_stack(self):
        c={'project':'cheesetrap-perf-a1', 'is_test':True}
        container={'Config':{'Labels':{'com.docker.compose.project':c['project'],'com.docker.compose.service':'worker'},'Env':[]}, 'NetworkSettings':{'Networks':{'test':{}}}}
        m.validate_runtime(c,[container],{'test':{'Internal':True}})
        for changed in [dict(c,is_test=False),dict(c,project='production')]:
            with self.assertRaises(ValueError):m.validate_runtime(changed,[container],{'test':{'Internal':True}})
        container['Config']['Env']=['CHEESETRAP_SMTP_SECRET_FILE=/secret']
        with self.assertRaises(ValueError):m.validate_runtime(c,[container],{'test':{'Internal':True}})

if __name__=='__main__':unittest.main()
