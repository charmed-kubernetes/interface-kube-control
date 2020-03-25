from unittest.mock import MagicMock
import provides


def test_set_default_cni():
    provider = provides.KubeControlProvider()
    provider.relations = [MagicMock(), MagicMock()]
    provider.set_default_cni('test')
    for relation in provider.relations:
        relation.to_publish.__setitem__.assert_called_once_with(
            'default-cni',
            'test'
        )
