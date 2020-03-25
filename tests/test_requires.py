import requires


def test_get_default_cni():
    requirer = requires.KubeControlRequirer()
    requirer.all_joined_units.received = {'default-cni': 'test'}
    assert requirer.get_default_cni() == 'test'
