import re
import base64
import binascii
import gzip
from hashlib import sha1
from dataclasses import dataclass
from typing import Sequence, Mapping, Optional, Self, Any

from .types import DictLayers, TsharkRaw


def get_layers_mapping(traffic: Sequence[DictLayers]) -> Mapping[int, DictLayers]:
    """Get mapping of layers by frame number (once for all)."""
    mapping: dict[int, DictLayers] = {}
    for layers in traffic:
        frame_number = int(layers.get('frame', {}).get('frame.number', -1))
        if frame_number >= 0:
            assert frame_number not in mapping, frame_number
            mapping[frame_number] = layers
    return mapping


def get_tshark_bytes_from_raw(r: Optional[TsharkRaw]) -> bytes:
    """Format of '*_raw' fields produced with '-x' flag: [hexa: str, *sizes: int]"""
    if r is None:
        return b''
    assert isinstance(r, list) and len(r) == 5, r
    hexa = r[0]
    assert isinstance(hexa, str) and hexa.isascii(), hexa
    return binascii.unhexlify(hexa)

TSHARK_CONTENT_ENCODED_RX = re.compile(
    r'^Content-encoded entity body \((?P<encoding>[^\)]+)\): (?P<len_encoded>\d+) bytes(?: -> (?P<len_decoded>\d+) bytes)?$'
)

@dataclass(frozen=True)
class ContentEncodedKey:
    encoding: str
    len_encoded: int
    len_decoded: Optional[int]


def get_tshark_content_encoded_key_value(http_layer: Mapping[str, Any]) -> tuple[ContentEncodedKey | None, Any | None]:
    for k, v in http_layer.items():
        if (m := TSHARK_CONTENT_ENCODED_RX.match(k)):
            g = m.groupdict()
            parsed_key = ContentEncodedKey(g['encoding'], int(g['len_encoded']), None if g['len_decoded'] is None else int(g['len_decoded']))
            return parsed_key, v
    return None, None


def get_consistent_http_content_length(
    headers_map: Mapping[str, str],
    declared_encoded_length: str | int | None,
    content_encoded_key: ContentEncodedKey | None,
    decoded_length: int,
) -> tuple[int, int]:
    """Returns (encoded content length, decoded content length)."""
    encoded_lengths: dict[str, int] = {}
    decoded_lengths = {'payload': decoded_length}
    declared_encoding = headers_map.get('content-encoding', 'identity').lower()
    no_compression = declared_encoding in {'identity', 'encrypted'}
    if content_encoded_key:
        assert content_encoded_key.encoding == declared_encoding, (content_encoded_key.encoding, declared_encoding)
        # <!> this is without padding, so it may slightly differ from http length (which includes padding...)
        encoded_lengths['tshark_encoded'] = content_encoded_key.len_encoded
        if content_encoded_key.len_decoded is not None:
            decoded_lengths['tshark_decoded'] = content_encoded_key.len_decoded
    elif decoded_length and not no_compression:
        raise NotImplementedError(f"tshark did not handle '{declared_encoding}' encoding ({decoded_length} data bytes)")
    if declared_encoded_length is not None:
        encoded_lengths['header'] = int(declared_encoded_length)
    if encoded_lengths:
        assert len(set(encoded_lengths.values())) == 1, encoded_lengths
        if no_compression:
            decoded_lengths.update(encoded_lengths)
    else:
        assert not decoded_length or no_compression, (declared_encoding, decoded_length)
        encoded_lengths = decoded_lengths
    assert len(set(decoded_lengths.values())) == 1, decoded_lengths
    return next(iter(encoded_lengths.values())), next(iter(decoded_lengths.values()))


ALLOWED_NON_PRINTABLE_CHARS = str.maketrans('', '', '\t\n\r')


@dataclass(frozen=True, repr=False)
class Payload:
    """Representation of either bytes, possibly representing UTF8 plain-text (useful for HAR export)."""

    bytes_: bytes = b''

    @property
    def size(self) -> int:
        return len(self.bytes_)  # <!> len('€') == 1 != len('€'.encode()) == 3

    def __bool__(self) -> bool:
        return bool(self.bytes_)

    def __repr__(self) -> str:
        if not self:
            return "Payload(size=0)"
        return f"Payload(size={self.size}, sha1={sha1(self.bytes_).hexdigest()})"

    @classmethod
    def concat(cls, *payloads: Self) -> Self:
        """Concatenate all payloads in order."""
        concat_bytes = b''.join(p.bytes_ for p in payloads)  # can't use `sum` here
        return cls(concat_bytes)

    @classmethod
    def from_tshark_raw(cls, data: Optional[TsharkRaw]) -> Self:
        """New payload from special tshark '*_raw' field"""
        return cls(get_tshark_bytes_from_raw(data))

    def to_har_dict(self) -> dict[str, Any]:
        """Export with HAR syntax."""
        try:
            plain_txt = self.bytes_.decode()
            assert plain_txt.translate(ALLOWED_NON_PRINTABLE_CHARS).isprintable()
            return {
                "size": self.size,
                "text": plain_txt,
            }
        except:
            pass
        return {
            "size": self.size,
            "text": base64.b64encode(self.bytes_).decode("ascii"),
            "encoding": "base64",
        }
