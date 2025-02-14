# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.
"""Implementation of kube-control interface (requires)

This re-implements the requires side of the interface in ops.framework
style rather than the reactive style.
"""

import base64
import logging
from functools import cached_property
from os import PathLike
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

import yaml
from pydantic import ValidationError

import ops

from .model import AuthRequest, Creds, Data, Label, Taint

log = logging.getLogger("KubeControlRequirer")
JUJU_CLUSTER = "juju-cluster"
JUJU_CONTEXT = "juju-context"


class RelationNotReady(Exception):
    """Exception raised when the relation is not ready."""


class KubeControlRequirer(ops.Object):
    """
    Implements the requirer side of the kube-control interface.
    """

    def __init__(self, charm: ops.CharmBase, endpoint: str = "kube-control", schemas="0"):
        super().__init__(charm, f"relation-{endpoint}")
        self.endpoint = endpoint
        # comma-separated set of schemas to advertise support
        # schema 0 -- same as unschema'd
        # schema 1 -- signals support for credentials in juju secrets
        self.schema_ver = [int(v) for v in schemas.split(",")]

    @cached_property
    def relation(self) -> Optional[ops.Relation]:
        """The lone relation endpoint or None."""
        return self.model.get_relation(self.endpoint)

    @cached_property
    def _data(self) -> Data:
        if self.relation and self.relation.units:
            rx: Dict[str, str] = {}
            for unit in self.relation.units:
                rx.update(self.relation.data[unit])
            return Data.model_validate(rx)
        raise RelationNotReady("No unit data available")

    def evaluate_relation(self, event) -> Optional[str]:
        """Determine if relation is ready."""
        no_relation = not self.relation or (
            isinstance(event, ops.RelationBrokenEvent) and event.relation is self.relation
        )
        if not self.is_ready:
            if no_relation:
                return f"Missing required {self.endpoint} relation"
            return f"Waiting for {self.endpoint} relation"
        return None

    @property
    def is_ready(self):
        """Whether the request for this instance has been completed."""
        try:
            self._data
        except ValidationError as ve:
            log.error(f"{self.endpoint} relation data not yet valid. ({ve}")
            return False
        except RelationNotReady:
            log.error(f"{self.endpoint} relation data not yet available.")
            return False
        return True

    def create_kubeconfig(self, ca: PathLike, kubeconfig: PathLike, user: str, k8s_user: str):
        """Write kubeconfig based on available creds."""
        creds = self.get_auth_credentials(k8s_user)
        endpoints = self.get_api_endpoints()
        server = endpoints[0] if endpoints else None
        token = creds["client_token"] if creds else None

        if ca_content := self.get_ca_certificate():
            ca_b64 = base64.b64encode(ca_content).decode("utf-8")
        elif Path(ca).exists():
            ca_b64 = base64.b64encode(Path(ca).read_bytes()).decode("utf-8")
        else:
            log.error("No CA certificate found")
            raise FileNotFoundError("No CA certificate found")

        # Create the config file with the address of the control-plane server.
        config_contents = {
            "apiVersion": "v1",
            "kind": "Config",
            "preferences": {},
            "clusters": [
                {
                    "cluster": {
                        "certificate-authority-data": ca_b64,
                        "server": server,
                    },
                    "name": JUJU_CLUSTER,
                }
            ],
            "contexts": [
                {
                    "context": {"cluster": JUJU_CLUSTER, "user": user},
                    "name": JUJU_CONTEXT,
                }
            ],
            "users": [{"name": user, "user": {"token": token}}],
            "current-context": JUJU_CONTEXT,
        }
        old_kubeconfig = Path(kubeconfig)
        new_kubeconfig = Path(f"{kubeconfig}.new")
        new_kubeconfig.parent.mkdir(exist_ok=True, mode=0o750)
        new_kubeconfig.write_text(yaml.safe_dump(config_contents))
        new_kubeconfig.chmod(mode=0o600)

        if old_kubeconfig.exists():
            changed = new_kubeconfig.read_text() != old_kubeconfig.read_text()
        else:
            changed = True
        if changed:
            new_kubeconfig.rename(old_kubeconfig)

    def get_ca_certificate(self) -> Optional[bytes]:
        """Return the CA certificate in pem format."""
        if not self.is_ready:
            return None

        return self._data.get_ca_certificate(self.model)

    def get_auth_credentials(self, user) -> Optional[Mapping[str, str]]:
        """Return the authentication credentials."""
        if not self.is_ready:
            return None

        users: Dict[str, Creds] = self._data.creds

        if creds := users.get(user):
            return {
                "user": user,
                "kubelet_token": creds.load_kubelet_token(self.model, user),
                "proxy_token": creds.load_proxy_token(self.model, user),
                "client_token": creds.load_client_token(self.model, user),
            }
        return None

    def get_dns(self) -> Mapping[str, Any]:
        """
        Return DNS info provided by the control-plane.
        """
        return {
            "port": self._data.port if self.is_ready else None,
            "domain": self._data.domain if self.is_ready else None,
            "sdn-ip": self._data.sdn_ip if self.is_ready else None,
            "enable-kube-dns": self._data.enable_kube_dns if self.is_ready else None,
        }

    def dns_ready(self) -> bool:
        """
        Return True if we have all DNS info from the control-plane.
        """
        keys = ["port", "domain", "sdn-ip", "enable-kube-dns"]
        dns_info = self.get_dns()
        return set(dns_info.keys()) == set(keys) and dns_info["enable-kube-dns"] is not None

    def set_auth_request(self, user, group="system:nodes") -> None:
        """Notify control-plane that we are requesting auth.

        Also, use this hostname for the kubelet system account.

        @params user   - user requesting authentication
        @params groups - Determines the level of elevated privileges of the
                         requested user.
                         Can be overridden to request sudo level access on the
                         cluster via changing to
                         system:masters.  # wokeignore:rule=master
        """
        if not self.relation:
            return

        req = AuthRequest(kubelet_user=user, auth_group=group)
        req.schema_vers = self.schema_ver
        log.info(f"Auth Req for {user} with group {group} on schema {self.schema_ver}")
        self.relation.data[self.model.unit].update(
            req.model_dump(exclude_none=True, by_alias=True)
        )

    def set_gpu(self, enabled=True):
        """
        Tell the control-plane that we're gpu-enabled (or not).
        """
        log.info("Setting gpu=%s on kube-control relation", enabled)
        for relation in self.model.relations:
            relation.data[self.model.unit].update(dict(gpu=enabled))

    def get_cluster_tag(self):
        """
        Tag for identifying resources that are part of the cluster.
        """
        return self._data.cluster_tag if self.is_ready else None

    def get_registry_location(self):
        """
        URL for container image registry.
        """
        return self._data.registry_location if self.is_ready else None

    @property
    def cohort_keys(self):
        """
        The cohort snapshot keys sent by the control-plane.
        """
        return self._data.cohort_keys if self.is_ready else None

    def get_default_cni(self):
        """
        Default CNI network to use.
        """
        return self._data.default_cni if self.is_ready else None

    def get_api_endpoints(self):
        """
        Returns a list of API endpoint URLs.
        """
        api_endpoints = (self.is_ready and self._data.api_endpoints) or []
        endpoints = set(map(str, api_endpoints))
        return sorted(endpoints)

    @property
    def has_xcp(self):
        """The has-xcp value."""
        return (self.is_ready and self._data.has_xcp) or False

    def get_controller_taints(self) -> List[Taint]:
        """Returns a list of taints configured on the control-plane nodes."""
        return (self.is_ready and self._data.taints) or []

    def get_controller_labels(self) -> List[Label]:
        """Returns a list of lables configured on the control-plane nodes."""
        return (self.is_ready and self._data.labels) or []
