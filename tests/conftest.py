import sys
from unittest.mock import MagicMock

charmhelpers = MagicMock()
sys.modules['charmhelpers'] = charmhelpers
sys.modules['charmhelpers.core'] = charmhelpers.core
sys.modules['charmhelpers.core.hookenv'] = charmhelpers.core.hookenv

charms = MagicMock()
sys.modules['charms'] = charms
sys.modules['charms.reactive'] = charms.reactive


class MockEndpoint(MagicMock):
    @property
    def endpoint_name(self):
        return 'kube-control'

    def expand_name(self, name):
        return name.replace('{endpoint_name}', self.endpoint_name)


charms.reactive.Endpoint = MockEndpoint
