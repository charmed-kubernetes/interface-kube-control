# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
import contextlib
import json
from collections import defaultdict
import unittest.mock as mock
from pathlib import Path

import pytest
import yaml
from ops.charm import CharmBase
from ops.interface_kube_control import KubeControlProvides


@pytest.fixture(scope="function")
def kube_control_provider():
    mock_charm = mock.MagicMock(auto_spec=CharmBase)
    mock_charm.framework.model.unit.name = "controller/0"
    yield KubeControlProvides(mock_charm)


@pytest.fixture()
def relation_data():
    yield yaml.safe_load_all(Path("tests/data/kube_control_request.yaml").open())


@contextlib.contextmanager
def mock_relations(num):
    class Relation(mock.MagicMock):
        data = defaultdict(dict)
        units = []

    with mock.patch(
        "ops.interface_kube_control.KubeControlProvides.relations",
        new_callable=mock.PropertyMock,
    ) as mock_prop:
        mock_prop.return_value = []
        for _ in range(num):
            mock_prop.return_value.append(Relation())
        yield mock_prop


def mock_units(relation, data):
    for unit_data in data:
        unit = mock.MagicMock()
        unit.name = unit_data["unit"]
        relation.data[unit] = unit_data["data"]
        relation.units.append(unit)


def test_set_default_cni(kube_control_provider):
    with mock_relations(2):
        kube_control_provider.set_default_cni("test")
        for relation in kube_control_provider.relations:
            assert relation.data[kube_control_provider.unit]["default-cni"] == '"test"'


@pytest.mark.parametrize(
    "taints, expected",
    [
        ([], []),
        (
            ["test.io/key=value:NoSchedule"],
            ["test.io/key=value:NoSchedule"],
        ),
        (
            ["test.io/key:NoSchedule"],
            ["test.io/key:NoSchedule"],
        ),
        (
            ["test.io/key=:NoSchedule"],
            ["test.io/key=:NoSchedule"],
        ),
        (
            [
                "test.io/key1=:NoSchedule",
                "test.io/key1=:NoSchedule",
                "test.io/key2=:NoSchedule",
            ],
            ["test.io/key1=:NoSchedule", "test.io/key2=:NoSchedule"],
        ),
    ],
    ids=[
        "empty",
        "str taint with value",
        "str taint without value",
        "str taint with empty string value",
        "2 identical, 1 unique str taints",
    ],
)
def test_set_taints(kube_control_provider, taints, expected):
    with mock_relations(2):
        kube_control_provider.set_taints(taints)
        for relation in kube_control_provider.relations:
            assert (
                json.loads(relation.data[kube_control_provider.unit]["taints"])
                == expected
            )


@pytest.mark.parametrize(
    "labels, expected",
    [
        ([], []),
        (
            ["test.io/key=value"],
            ["test.io/key=value"],
        ),
        (
            ["test.io/key="],
            ["test.io/key="],
        ),
        (
            ["test.io/key1=value", "test.io/key1=value", "test.io/key2=value"],
            ["test.io/key1=value", "test.io/key2=value"],
        ),
    ],
    ids=[
        "empty",
        "str label with value",
        "str label with empty string value",
        "2 identical, 1 unique str taints",
    ],
)
def test_set_labels(kube_control_provider, labels, expected):
    with mock_relations(2):
        kube_control_provider.set_labels(labels)
        for relation in kube_control_provider.relations:
            assert (
                json.loads(relation.data[kube_control_provider.unit]["labels"])
                == expected
            )


def test_is_ready_no_relation(kube_control_provider):
    with mock_relations(0):
        assert kube_control_provider.auth_requests == []


@mock.patch("ops.interface_kube_control.KubeControlProvides.refresh_secret_content")
def test_set_ca_certificate(refresh_secret_content, kube_control_provider):
    with mock_relations(2):
        mock_secret = refresh_secret_content.return_value
        mock_secret.id = "abcd::1234"
        data = Path("tests/data/test-ca-cert.pem").read_text()
        kube_control_provider.set_ca_certificate(data)
        for relation in kube_control_provider.relations:
            assert (
                relation.data[kube_control_provider.unit]["ca-certificate-secret-id"]
                == "abcd::1234"
            )
        refresh_secret_content.assert_called_once()
        (label, content, description), _ = refresh_secret_content.call_args
        assert label == "ca-certificate"
        assert content == {"ca-certificate": data}
        assert description == "Kubernetes API endpoint CA certificate"


@mock.patch("ops.interface_kube_control.KubeControlProvides.refresh_secret_content")
def test_sign_auth_requests(
    refresh_secret_content, kube_control_provider, relation_data
):
    with mock_relations(1) as relations:
        relation = relations.return_value[0]
        mock_units(relation, relation_data)
        mock_secret = refresh_secret_content.return_value
        mock_secret.id = "abcd::1234"

        for request in kube_control_provider.auth_requests:
            kube_control_provider.sign_auth_request(
                request, "client", "kubelet", "proxy"
            )

    crafted_creds = relation.data[kube_control_provider.unit]["creds"]
    creds = json.loads(crafted_creds)
    assert creds == {
        "system:node:node-1": {
            "scope": "requirer/0",
            "client_token": "client",
            "kubelet_token": "kubelet",
            "proxy_token": "proxy",
        },
        "system:node:node-2": {
            "scope": "requirer/1",
            "secret-id": "abcd::1234",
            "client_token": "",
            "kubelet_token": "",
            "proxy_token": "",
        },
    }
