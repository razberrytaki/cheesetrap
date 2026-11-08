import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('network_fixture', Path(__file__).with_name('network_fixture.py'))
n = importlib.util.module_from_spec(spec)
spec.loader.exec_module(n)


class MetadataRouteTests(unittest.TestCase):
 def test_metadata_route_requires_exact_mock_hop_and_prohibit(self):
  routes=[{'dst':'169.254.169.254','gateway':'172.20.255.254','dev':'eth0','metric':1},{'type':'prohibit','dst':'169.254.169.254','metric':32760}]
  lookup=[{'dst':'169.254.169.254','gateway':'172.20.255.254','dev':'eth0'}]
  n.validate_metadata_route(routes,lookup,'172.20.255.254')
  for bad in [[],routes[:1],[dict(routes[0],gateway='172.20.0.1'),routes[1]]]:
   with self.assertRaises(ValueError): n.validate_metadata_route(bad,lookup,'172.20.255.254')
  with self.assertRaises(ValueError): n.validate_metadata_route(routes,[dict(lookup[0],gateway='172.20.0.1')],'172.20.255.254')


if __name__ == '__main__':
    unittest.main()
