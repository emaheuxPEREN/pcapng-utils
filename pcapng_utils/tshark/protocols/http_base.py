from abc import ABC, abstractmethod
from datetime import datetime, timezone
from dataclasses import dataclass
from typing import ClassVar, Any

from ..types import DictLayers
from ..utils import Payload

HTTP_METHODS = {'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'CONNECT', 'TRACE'}


@dataclass(frozen=True)
class BaseHttpRequestResponse(ABC):
    """Base class for HTTP request or response."""

    packet_layers: DictLayers
    """All tshark layers for this packet"""

    FALLBACK_CONTENT_TYPE: ClassVar = 'application/octet-stream'

    @property
    def community_id(self) -> str:
        return self.packet_layers['communityid']

    @property
    def ip_layer(self) -> dict[str, Any]:
        return self.packet_layers['ip']

    @property
    def frame_layer(self) -> dict[str, Any]:
        return self.packet_layers['frame']

    @property
    def src_ip(self) -> str:
        return self.ip_layer['ip.src']

    @property
    def dst_ip(self) -> str:
        return self.ip_layer['ip.dst']

    @property
    def src_host(self) -> str:  # unused
        return self.ip_layer.get('ip.src_host', '')

    @property
    def dst_host(self) -> str:  # unused
        return self.ip_layer.get('ip.dst_host', '')

    @property
    def started_date(self) -> str:
        frame_time: str = self.frame_layer['frame.time_epoch']
        return datetime.fromtimestamp(float(frame_time), timezone.utc).isoformat()

    @property
    @abstractmethod
    def header_length(self) -> int:
        """Byte length of headers"""

    @property
    @abstractmethod
    def content_length(self) -> int:
        """Byte length of encoded payload"""

    @property
    @abstractmethod
    def payload(self) -> Payload:
        """Decoded payload"""

    def to_har(self) -> dict[str, Any]:
        # TODO
        pass

    # TODO? headers_map from stashed home code

class BaseHttpRequest(BaseHttpRequestResponse):

    @property
    def uri(self) -> str: ...

    # TODO: http_version & method

class BaseHttpResponse(BaseHttpRequestResponse):

    # TODO: http_version & status code+text

    pass
