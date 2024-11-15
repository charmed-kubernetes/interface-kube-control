import json
import logging

from .model import AuthRequest, Creds, Label, Taint
from ops import CharmBase, Relation, SecretNotFoundError, Unit
from typing import Generator, List, Tuple

log = logging.getLogger("KubeControlProvides")


class KubeControlProvides:
    """Implements the Provides side of the kube-control interface."""

    def __init__(self, charm: CharmBase, endpoint: str = "kube-control", schemas="0,1"):
        self.charm = charm
        self.endpoint = endpoint

    @property
    def auth_requests(self) -> List[AuthRequest]:
        """Return a list of authentication requests from related units."""
        requests = [
            request
            for relation in self.relations
            for unit in relation.units
            if (request := AuthRequest(unit=unit.name, **relation.data[unit]))
            and request.user
            and request.group
        ]
        requests.sort()
        return requests

    def clear_creds(self) -> None:
        """Clear creds from the relation. This is used by non-leader units to
        stop advertising creds so that the leader can assume full control of
        them.
        """
        for relation in self.relations:
            relation.data[self.unit]["creds"] = ""

    @property
    def ingress_addresses(self) -> List[str]:
        """Ingress addresses for this endpoint."""
        return [
            # RFC 5280 section 4.2.1.6: "For IP version 6 ... the octet string
            # MUST contain exactly sixteen octets." We'll use .exploded to be
            # safe.
            addr.exploded
            for addr in self.charm.model.get_binding(
                self.endpoint
            ).network.ingress_addresses
        ]

    @property
    def relations(self) -> List[Relation]:
        """List of relations on this endpoint."""
        return self.charm.model.relations[self.endpoint]

    def set_api_endpoints(self, endpoints) -> None:
        """Send the list of API endpoint URLs to which workers should connect."""
        endpoints = json.dumps(endpoints)
        for relation in self.relations:
            relation.data[self.unit]["api-endpoints"] = endpoints

    def set_ca_certificate(self, ca_certificate: str) -> None:
        """Send the CA certificate to the remote units.

        Args:
            ca_certificate str: The CA certificate in PEM format.
        """
        content = {"ca-certificate": ca_certificate}
        secret = self.refresh_secret_content(
            "ca-certificate", content, "Kubernetes API endpoint CA certificate"
        )
        for relation in self.relations:
            if secret.id:
                secret.grant(relation)
                relation.data[self.unit]["ca-certificate-secret-id"] = secret.id

    def set_cluster_name(self, cluster_name) -> None:
        """Send the cluster name to the remote units."""
        for relation in self.relations:
            relation.data[self.unit]["cluster-tag"] = cluster_name

    def set_default_cni(self, default_cni) -> None:
        """Send the default CNI. The default_cni value should be a string
        containing the name of a related CNI application to use as the default
        CNI. For example: "flannel" or "calico". If no default has been chosen
        then "" can be sent instead."""
        value = json.dumps(default_cni)
        for relation in self.relations:
            relation.data[self.unit]["default-cni"] = value

    def set_dns_address(self, address) -> None:
        """Send DNS address to the remote units for use in Kubelet configuration.
        This will typically be the cluster IP of the kube-dns service belonging
        to CoreDNS."""
        for relation in self.relations:
            relation.data[self.unit]["sdn-ip"] = address

    def set_dns_domain(self, domain) -> None:
        """Send DNS domain to the remote units for use in Kubelet configuration."""
        for relation in self.relations:
            relation.data[self.unit]["domain"] = domain

    def set_dns_enabled(self, enabled) -> None:
        """Send DNS enabled status. This indicates to remote units if they should
        wait for DNS info or not."""
        value = str(enabled)
        for relation in self.relations:
            relation.data[self.unit]["enable-kube-dns"] = value

    def set_dns_port(self, port) -> None:
        """Send DNS port to the remote units for use in Kubelet configuration."""
        value = str(port)
        for relation in self.relations:
            relation.data[self.unit]["port"] = value

    def set_has_external_cloud_provider(self, has_xcp) -> None:
        """Send indicator to remote units that an external cloud provider is in use."""
        value = str(has_xcp).lower()
        for relation in self.relations:
            relation.data[self.unit]["has-xcp"] = value

    def set_image_registry(self, image_registry) -> None:
        """Send the image registry location to the remote units."""
        for relation in self.relations:
            relation.data[self.unit]["registry-location"] = image_registry

    def set_labels(self, labels) -> None:
        """Send the Juju config labels of the control-plane."""
        labels = [str(_) for _ in labels if Label.validate(_)]
        dedup = sorted(set(labels))
        value = json.dumps(dedup)
        for relation in self.relations:
            relation.data[self.unit]["labels"] = value

    def set_taints(self, taints) -> None:
        """Send the Juju config taints of the control-plane."""
        taints = [str(_) for _ in taints if Taint.validate(_)]
        dedup = sorted(set(taints))
        value = json.dumps(dedup)
        for relation in self.relations:
            relation.data[self.unit]["taints"] = value

    def refresh_secret_content(self, label, content, description=None):
        """Refresh the content of a secret."""
        try:
            secret = self.charm.model.get_secret(label=label)
            if secret.get_content(refresh=True) != content:
                secret.set_content(content)
            secret.set_info(description=description, label=label)
        except SecretNotFoundError:
            secret = self.charm.app.add_secret(
                content, label=label, description=description
            )
        return secret

    def closed_auth_creds(self) -> Generator[Tuple[str, Creds], None, None]:
        """Revoke tokens for units removed from the relation.

        Example:
        ```python
            for user, cred in self.kube_control.closed_auth_creds():
                log.info("Revoke auth-token for '%s'", user)
                token = cred.client_token.get_secret_value()
                kubernetes.remove_auth_token(token)
        ```

        Yields:
            Tuple[str, Creds]: The user and creds to be revoked.
        """
        creds, unit_names = {}, []

        # Collect creds from all relations
        for relation in self.relations:
            creds.update(json.loads(relation.data[self.unit].get("creds", "{}")))
            unit_names += [u.name for u in relation.units]

        # Revoke creds for units that have been removed
        for user, cred in dict(**creds).items():
            data = Creds(**cred)
            if data.scope not in unit_names:
                log.info(f"Revoking creds for {user} on unit {data.scope}")
                creds.pop(user)
                yield user, data
                if data.secret_id:
                    secret = self.charm.model.get_secret(id=data.secret_id)
                    secret.remove_all_revisions()

        # Publish the updated creds without the revoked units
        value = json.dumps(creds)
        for relation in self.relations:
            relation.data[self.unit]["creds"] = value

    def sign_auth_request(
        self, request: AuthRequest, client_token, kubelet_token, proxy_token
    ) -> None:
        """Send authorization tokens to the requesting unit."""
        creds, request_relation = {}, None
        request_unit = self.charm.model.get_unit(request.unit)

        for relation in self.relations:
            creds.update(json.loads(relation.data[self.unit].get("creds", "{}")))
            if request_unit in relation.units:
                request_relation = relation

        tokens = Creds(
            client_token=client_token,
            kubelet_token=kubelet_token,
            proxy_token=proxy_token,
            scope=request.unit,
        )

        if 1 in request.schema_vers and request_relation:
            # Requesting unit can use schema 1, use juju secrets
            content = {
                "client-token": client_token,
                "kubelet-token": kubelet_token,
                "proxy-token": proxy_token,
            }
            label = f"{request.user}-creds"
            description = f"Credentials for {request.user}"
            secret = self.refresh_secret_content(label, content, description)
            if secret.id:
                log.info(f"Granting secret {secret.id} to {request_relation.name}")
                secret.grant(request_relation, unit=request_unit)
                # Intentionally set the tokens to empty strings in order to
                # be valid credentials for units still receiving these on schema 0
                # if None, these would be considered missing and the schema 0
                # parser would assume the relation wasn't ready.
                tokens.client_token = ""
                tokens.kubelet_token = ""
                tokens.proxy_token = ""
                tokens.secret_id = secret.id
                creds[request.user] = tokens.dict(by_alias=True, exclude_none=True)
        else:
            creds[request.user] = tokens.dict(by_alias=True, exclude_none=True)

        value = json.dumps(creds)
        for relation in self.relations:
            relation.data[self.unit]["creds"] = value

    @property
    def unit(self) -> Unit:
        """Local unit."""
        return self.charm.unit
