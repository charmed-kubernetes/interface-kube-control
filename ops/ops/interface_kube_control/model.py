from pydantic import Field, AnyHttpUrl, BaseModel, Json
import json
import ops
from typing import List, Dict, Optional
import re


class _ValidatedStr:
    def __init__(self, value, *groups) -> None:
        self._str = value
        self.groups = groups

    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v):
        if not isinstance(v, str):
            raise TypeError("string required")
        m = cls.REGEX.match(v)
        if not m:
            raise ValueError("invalid format")
        return cls(v, *m.groups())

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self._str},*{self.groups})"

    @property
    def key(self) -> str:
        return self.groups[0]

    @property
    def value(self) -> Optional[str]:
        return self.groups[1]


class Label(_ValidatedStr):
    REGEX = re.compile(r"^([\w\d\-\.\/]+)=([\w\d\-\.]*)$")


class Taint(_ValidatedStr):
    REGEX = re.compile(r"^([\w\d\-\.\/]+)(?:=([\w\d\-\.]*))?:([\w\d\-\.]+)$")

    @property
    def effect(self) -> str:
        return self.groups[2]


class AuthRequest(BaseModel):
    """Models the requests from the requirer side of the relation.

    Attributes:
        kubelet_user       str: name of the user the token is granted for
        auth_group         str: kubernetes group associated with the token
        schema_vers  list[int]: schemas versions supported by the requester
        unit               str: unit name requesting tokens, (only on provider)
        user               str: alias for kubelet_user
        group              str: alias for auth_group
    """

    kubelet_user: Optional[str]
    auth_group: Optional[str]
    schema_vers: Json[List[int]] = Field(default_factory=list)
    unit: Optional[str]

    def dict(self, **kwds):
        d = super().dict(**kwds)
        if schema_vers := d.pop("schema_vers", None):
            d["schema_vers"] = json.dumps(schema_vers)
        return d

    @property
    def user(self) -> Optional[str]:
        return self.kubelet_user

    @property
    def group(self) -> Optional[str]:
        return self.auth_group

    def __lt__(self, other):
        return (self.unit, self.kubelet_user, self.auth_group) < (
            other.unit,
            other.kubelet_user,
            other.auth_group,
        )


class Creds(BaseModel):
    client_token: str
    kubelet_token: str
    proxy_token: str
    scope: str
    secret_id: Optional[str] = Field(alias="secret-id", default=None)

    def _get_secret_content(self, model: ops.Model, user: str) -> Dict[str, str]:
        secret = model.get_secret(id=self.secret_id, label=f"{user}-creds")
        return secret.get_content(refresh=True)

    def load_client_token(self, model: ops.Model, user: str) -> str:
        if self.secret_id:
            return self._get_secret_content(model, user)["client-token"]
        return self.client_token

    def load_kubelet_token(self, model, user: str) -> str:
        if self.secret_id:
            return self._get_secret_content(model, user)["kubelet-token"]
        return self.kubelet_token

    def load_proxy_token(self, model, user: str) -> str:
        if self.secret_id:
            return self._get_secret_content(model, user)["proxy-token"]
        return self.proxy_token


class Data(BaseModel):
    api_endpoints: Json[List[AnyHttpUrl]] = Field(alias="api-endpoints")
    cluster_tag: str = Field(alias="cluster-tag")
    cohort_keys: Optional[Json[Dict[str, str]]] = Field(alias="cohort-keys")
    creds: Json[Dict[str, Creds]] = Field(alias="creds")
    default_cni: Json[str] = Field(alias="default-cni")
    domain: str = Field(alias="domain")
    enable_kube_dns: bool = Field(alias="enable-kube-dns")
    has_xcp: Json[bool] = Field(alias="has-xcp")
    port: Json[int] = Field(alias="port")
    sdn_ip: Optional[str] = Field(default=None, alias="sdn-ip")
    registry_location: str = Field(alias="registry-location")
    taints: Optional[Json[List[Taint]]] = Field(alias="taints", default=None)
    labels: Optional[Json[List[Label]]] = Field(alias="labels", default=None)
