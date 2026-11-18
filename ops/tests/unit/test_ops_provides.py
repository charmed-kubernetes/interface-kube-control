# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
import contextlib
import json
from collections import defaultdict
from pathlib import Path
from typing import ClassVar
from unittest import mock

import ops
import pytest
import yaml
from ops.charm import CharmBase
from ops.interface_kube_control import KubeControlProvides
from ops.interface_kube_control.model import Creds


@pytest.fixture(scope="function")
def kube_control_provider():
    mock_charm = mock.MagicMock(auto_spec=CharmBase)
    mock_charm.framework.model.unit.name = "controller/0"
    yield KubeControlProvides(mock_charm)


@pytest.fixture()
def relation_data():
    yield yaml.safe_load_all(Path("tests/data/kube_control_request.yaml").read_text())


@contextlib.contextmanager
def mock_relations(num):
    class Relation(mock.MagicMock):
        data: ClassVar = defaultdict(dict)
        units: ClassVar = []

    with mock.patch(
        "ops.interface_kube_control.KubeControlProvides.relations",
        new_callable=mock.PropertyMock,
    ) as mock_prop:
        mock_prop.return_value = []
        for _ in range(num):
            mock_prop.return_value.append(Relation())
        yield mock_prop


def mock_units(model, relation, data):
    relation._units_by_name = {}
    for unit_data in data:
        unit = mock.MagicMock()
        unit.name = unit_data["unit"]
        relation._units_by_name[unit.name] = unit
        relation.data[unit] = unit_data["data"]
        relation.units.append(unit)
    model.get_unit.side_effect = relation._units_by_name.__getitem__


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
            assert json.loads(relation.data[kube_control_provider.unit]["taints"]) == expected


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
            assert json.loads(relation.data[kube_control_provider.unit]["labels"]) == expected


def test_is_ready_no_relation(kube_control_provider):
    with mock_relations(0):
        assert kube_control_provider.auth_requests == []


@mock.patch("ops.interface_kube_control.KubeControlProvides._refresh_secret_content")
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


@mock.patch("ops.interface_kube_control.KubeControlProvides._refresh_secret_content")
def test_set_ca_certificate_existing_secret_without_id(
    refresh_secret_content, kube_control_provider
):
    """A secret fetched by label has no id; it must still be granted and published."""
    with mock_relations(2):
        found = refresh_secret_content.return_value
        found.id = None
        found.get_info.return_value.id = "abcd::1234"
        resolved = kube_control_provider.charm.model.get_secret.return_value
        kube_control_provider.set_ca_certificate("cert")
        kube_control_provider.charm.model.get_secret.assert_called_once_with(
            id="abcd::1234", label="ca-certificate"
        )
        assert resolved.grant.call_count == 2
        for relation in kube_control_provider.relations:
            resolved.grant.assert_any_call(relation)
            assert (
                relation.data[kube_control_provider.unit]["ca-certificate-secret-id"]
                == "abcd::1234"
            )


@mock.patch("ops.interface_kube_control.KubeControlProvides._refresh_secret_content")
def test_set_ca_certificate_unresolvable_secret_id(refresh_secret_content, kube_control_provider):
    with mock_relations(1):
        found = refresh_secret_content.return_value
        found.id = None
        found.get_info.side_effect = ops.SecretNotFoundError
        kube_control_provider.set_ca_certificate("cert")
        found.grant.assert_not_called()
        for relation in kube_control_provider.relations:
            assert "ca-certificate-secret-id" not in relation.data[kube_control_provider.unit]


@pytest.mark.parametrize("error", [ops.ModelError, ops.SecretNotFoundError])
@mock.patch("ops.interface_kube_control.KubeControlProvides._refresh_secret_content")
def test_set_ca_certificate_grant_fails_on_departing_relation(
    refresh_secret_content, error, kube_control_provider, caplog
):
    """A relation being torn down rejects the grant; other relations must still be served."""
    with mock_relations(2):
        secret = refresh_secret_content.return_value
        secret.id = "abcd::1234"
        secret.grant.side_effect = [error("relation is dying"), None]
        kube_control_provider.set_ca_certificate("cert")
        departing, healthy = kube_control_provider.relations
        assert [c.args[0] for c in secret.grant.call_args_list] == [departing, healthy]
        assert "Unable to publish CA secret" in caplog.text
        assert "relation is dying" in caplog.text


def test_refresh_secret_content_existing(kube_control_provider):
    content = {"key": "new"}
    expected_content = {**content, "endpoint": kube_control_provider.endpoint}
    cur_secret = mock.MagicMock(autospec=ops.Secret)
    kube_control_provider.charm.model.get_secret.return_value = cur_secret
    cur_secret.get_info.return_value.revision = 1
    cur_secret.get_content.return_value = {"key": "current"}
    sec = kube_control_provider._refresh_secret_content("label", content, "description")
    assert sec is cur_secret
    sec.get_content.assert_called_once_with(refresh=True)
    sec.set_content.assert_called_once_with(expected_content)


def test_refresh_secret_content_new(kube_control_provider):
    content = {"key": "new"}
    expected_content = {**content, "endpoint": kube_control_provider.endpoint}
    kube_control_provider.charm.model.get_secret.side_effect = ops.SecretNotFoundError
    new_secret = mock.MagicMock(autospec=ops.Secret)
    kube_control_provider.charm.app.add_secret.return_value = new_secret
    sec = kube_control_provider._refresh_secret_content("label", content, "description")
    assert sec is new_secret
    kube_control_provider.charm.app.add_secret.assert_called_once_with(
        expected_content, label="label", description="description"
    )


def test_close_auth_requests(kube_control_provider, relation_data):
    with mock_relations(1) as relations:
        relation = relations.return_value[0]
        mock_units(kube_control_provider.charm.model, relation, relation_data)
        get_secret = kube_control_provider.charm.model.get_secret
        relation.data[kube_control_provider.unit]["creds"] = json.dumps(
            {
                "system:node:node-3": {
                    "scope": "requirer/2",
                    "client_token": "client",
                    "kubelet_token": "kubelet",
                    "proxy_token": "proxy",
                },
                "system:node:node-4": {
                    "scope": "requirer/3",
                    "secret-id": "abcd::1234",
                    "client_token": "",
                    "kubelet_token": "",
                    "proxy_token": "",
                },
            }
        )
        for user, creds in kube_control_provider.closed_auth_creds():
            assert user in ["system:node:node-3", "system:node:node-4"]
            assert creds.scope in ["requirer/2", "requirer/3"]

        get_secret.assert_called_once_with(id="abcd::1234")
        get_secret.return_value.remove_all_revisions.assert_called_once()
        assert relation.data[kube_control_provider.unit]["creds"] == "{}"


@mock.patch("ops.interface_kube_control.KubeControlProvides._refresh_secret_content")
def test_sign_auth_requests(refresh_secret_content, kube_control_provider, relation_data):
    with mock_relations(1) as relations:
        relation = relations.return_value[0]
        mock_units(kube_control_provider.charm.model, relation, relation_data)
        mock_secret = refresh_secret_content.return_value
        mock_secret.id = "abcd::1234"

        for request in kube_control_provider.auth_requests:
            kube_control_provider.sign_auth_request(request, "client", "kubelet", "proxy")

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


def _sign_all(provider):
    for request in provider.auth_requests:
        provider.sign_auth_request(request, "client", "kubelet", "proxy")


@mock.patch("ops.interface_kube_control.KubeControlProvides._refresh_secret_content")
def test_sign_auth_requests_unresolvable_secret_id(
    refresh_secret_content, kube_control_provider, relation_data, caplog
):
    """A schema 1 requester gets nothing, not plaintext tokens, when the secret id is unknown."""
    with mock_relations(1) as relations:
        relation = relations.return_value[0]
        mock_units(kube_control_provider.charm.model, relation, relation_data)
        found = refresh_secret_content.return_value
        found.id = None
        found.get_info.side_effect = ops.SecretNotFoundError

        _sign_all(kube_control_provider)

    creds = json.loads(relation.data[kube_control_provider.unit]["creds"])
    assert list(creds) == ["system:node:node-1"]
    assert creds["system:node:node-1"]["client_token"] == "client"
    found.grant.assert_not_called()
    assert "not sending credentials to requirer/1" in caplog.text


@mock.patch("ops.interface_kube_control.KubeControlProvides._refresh_secret_content")
def test_sign_auth_requests_grant_fails(
    refresh_secret_content, kube_control_provider, relation_data, caplog
):
    """A dying requester rejects the grant; its creds are withheld but others are published."""
    with mock_relations(1) as relations:
        relation = relations.return_value[0]
        mock_units(kube_control_provider.charm.model, relation, relation_data)
        secret = refresh_secret_content.return_value
        secret.id = "abcd::1234"
        secret.grant.side_effect = ops.ModelError("unit is dying")

        _sign_all(kube_control_provider)

    creds = json.loads(relation.data[kube_control_provider.unit]["creds"])
    assert list(creds) == ["system:node:node-1"]
    assert "Unable to grant secret abcd::1234 to requirer/1: unit is dying" in caplog.text


@mock.patch("ops.interface_kube_control.KubeControlProvides._refresh_secret_content")
def test_sign_auth_requests_existing_secret_without_id(
    refresh_secret_content, kube_control_provider, relation_data
):
    """A creds secret fetched by label has no id; it must still be granted and published."""
    with mock_relations(1) as relations:
        relation = relations.return_value[0]
        mock_units(kube_control_provider.charm.model, relation, relation_data)
        found = refresh_secret_content.return_value
        found.id = None
        found.get_info.return_value.id = "abcd::1234"
        resolved = kube_control_provider.charm.model.get_secret.return_value

        _sign_all(kube_control_provider)

    creds = json.loads(relation.data[kube_control_provider.unit]["creds"])
    assert creds["system:node:node-2"]["secret-id"] == "abcd::1234"
    resolved.grant.assert_called_once()


SCHEMA0_ENTRY = Creds(
    scope="requirer/1",
    client_token="old-client",
    kubelet_token="old-kubelet",
    proxy_token="old-proxy",
).model_dump(by_alias=True, exclude_none=True)
SCHEMA1_ENTRY = Creds(
    scope="requirer/1",
    secret_id="old::id",
    client_token="",
    kubelet_token="",
    proxy_token="",
).model_dump(by_alias=True, exclude_none=True)


def _sign_with_existing(provider, relation_data, existing, configure):
    """Sign all requests with `existing` creds already published for node-2."""
    with mock_relations(1) as relations:
        relation = relations.return_value[0]
        mock_units(provider.charm.model, relation, relation_data)
        relation.data[provider.unit]["creds"] = json.dumps({"system:node:node-2": existing})
        with mock.patch(
            "ops.interface_kube_control.KubeControlProvides._refresh_secret_content"
        ) as refresh:
            configure(refresh.return_value)
            _sign_all(provider)
    return json.loads(relation.data[provider.unit]["creds"])


def _unresolvable(secret):
    secret.id = None
    secret.get_info.side_effect = ops.SecretNotFoundError


def _grant_fails(secret):
    secret.id = "abcd::1234"
    secret.grant.side_effect = ops.ModelError("unit is dying")


@pytest.mark.parametrize("configure", [_unresolvable, _grant_fails])
def test_sign_auth_requests_failure_withholds_existing_plaintext(
    configure, kube_control_provider, relation_data
):
    """Schema 0 tokens published earlier are removed when the schema 1 upgrade cannot complete."""
    creds = _sign_with_existing(kube_control_provider, relation_data, SCHEMA0_ENTRY, configure)
    assert "system:node:node-2" not in creds
    assert creds["system:node:node-1"]["client_token"] == "client"


@pytest.mark.parametrize("configure", [_unresolvable, _grant_fails])
def test_sign_auth_requests_failure_keeps_existing_secret_entry(
    configure, kube_control_provider, relation_data
):
    """An entry that only references a secret holds no tokens and survives a failed grant."""
    creds = _sign_with_existing(kube_control_provider, relation_data, SCHEMA1_ENTRY, configure)
    assert creds["system:node:node-2"] == SCHEMA1_ENTRY
