# SPDX-FileCopyrightText: 2024 Pôle d'Expertise de la Régulation Numérique - PEReN <contact@peren.gouv.fr>
# SPDX-License-Identifier: MIT

import logging
from pathlib import Path
from operator import itemgetter
from collections import defaultdict
from collections.abc import Mapping
from typing import TypedDict, Literal, ClassVar, Any

import communityid
from sortedcontainers import SortedKeyList

from .base import HarEnrichment
from .types import CommunityID, Timestamp, FlowDirection
from .utils import keys_to_camel_case, clean_prefixed_ip_address

logger = logging.getLogger('enrichment')


class SocketTraceData(TypedDict):  # and other stuff that is not
    stack: list[dict]
    socketEventType: str
    localIp: str
    localPort: int
    destIp: str
    destPort: int
    socketType: Literal['tcp', 'udp', 'tcp6', 'udp6']
    communityId: CommunityID


class SocketTrace(TypedDict):
    process: str
    timestamp: Timestamp  # seconds
    data: SocketTraceData


def empty_time_sorted_list_of_stack_traces():
    return SortedKeyList(key=itemgetter('timestamp'))

# cf. https://docs.python.org/3.11/library/bisect.html#searching-sorted-lists
def get_index_le(lst: SortedKeyList, key: Any) -> int | None:
    ix: int = lst.bisect_key_right(key) - 1
    if ix == -1:
        return None
    return ix

def get_index_ge(lst: SortedKeyList, key: Any) -> int | None:
    ix: int = lst.bisect_key_left(key)
    if ix == len(lst):
        return None
    return ix


class Stacktrace(HarEnrichment):

    ID: ClassVar = 'stacktrace'

    KEYS_PREFIX: ClassVar = ''
    COMMUNITY_ID: ClassVar = communityid.CommunityID()
    MAX_DELTA_S: ClassVar[float] = 5.0
    """maximum delay (in seconds) tolerated between socket operation & network traffic for matching them"""

    def __init__(self, har_data: dict, input_data_file: Path) -> None:
        super().__init__(har_data, input_data_file)
        self.socket_traces_map: Mapping[tuple[CommunityID, FlowDirection], SortedKeyList] = defaultdict(empty_time_sorted_list_of_stack_traces)
        self.paired_socket_traces: dict[tuple[CommunityID, FlowDirection, int], float] = {}

        if self.can_enrich:
            # Preprocess the socket traces: remove unnecessary fields and prefix keys
            self._preprocess_socket_traces()
        else:
            logger.warning('HAR enrichment with stacktrace information cannot be performed, skip.')

    @classmethod
    def _attach_community_id_to_stacktrace(cls, socket_trace_data: dict) -> None:
        """Compute and append in-place the Community ID to the given stacktrace"""
        src_ip = clean_prefixed_ip_address(socket_trace_data['localIp'])
        src_port = socket_trace_data['localPort']
        dst_ip = clean_prefixed_ip_address(socket_trace_data['destIp'])
        dst_port = socket_trace_data['destPort']
        # Prepare the Community ID template based on the protocol
        if 'tcp' in socket_trace_data['socketType']:
            tpl = communityid.FlowTuple.make_tcp(src_ip, dst_ip, src_port, dst_port)
        else:
            tpl = communityid.FlowTuple.make_udp(src_ip, dst_ip, src_port, dst_port)
        # Attach the Community ID
        socket_trace_data['communityId'] = cls.COMMUNITY_ID.calc(tpl)

    @classmethod
    def _get_clean_stacktrace(cls, stacktrace: dict) -> SocketTrace:
        """
        Get a clean stacktrace object by removing unnecessary fields,
        renaming keys in camel case (with optional prefix) and ensuring the
        timestamp is in seconds (instead of milliseconds).

        Side-effects free.
        """
        clean_trace = keys_to_camel_case({
            'timestamp': stacktrace['timestamp'] / 1000.,
            'process': stacktrace['process'],
            'data': stacktrace['data'],
        }, prefix=cls.KEYS_PREFIX)
        cls._attach_community_id_to_stacktrace(clean_trace['data'])
        return clean_trace  # type: ignore

    def _preprocess_socket_traces(self) -> None:
        """Create the mapping of stock traces (by community ID + flow direction) to efficiently attach them afterwards."""
        assert isinstance(self.input_data, list), type(self.input_data)
        for raw_stack_trace in self.input_data:
            clean_stack_trace = self._get_clean_stacktrace(raw_stack_trace)
            socket_type = clean_stack_trace['data']['socketEventType']
            flow_dir: FlowDirection | None = 'out' if socket_type in {'write', 'sendto'} else 'in' if socket_type in {'read', 'recvfrom'} else None
            if flow_dir is None:
                continue
            # TODO: check that timestamp != of others?
            self.socket_traces_map[(clean_stack_trace['data']['communityId'], flow_dir)].add(clean_stack_trace)

    @staticmethod
    def _can_enrich_directed_entry(har_directed_entry: dict[str, Any]) -> bool:
        """Check if the given HAR entry can be enriched with stacktrace information"""
        return bool(har_directed_entry.get('_timestamp'))

    def _find_best_stacktrace(self, community_id: CommunityID, direction: FlowDirection, timestamp: Timestamp) -> SocketTrace | None:
        r"""
        Find the stacktrace with the closest\* timestamp to the given one matching the community ID

        \* (in the past if direction is `out`, in the future if direction was `in`)
        """
        matching_traces = self.socket_traces_map.get((community_id, direction))
        if not matching_traces:
            logger.warning(f'No stacktrace has been found for {community_id=}, {direction=}')
            return None
        if direction == 'out':
            chronology_label, delay_sign = f'just before {timestamp=}', -1
            closest_stack_trace_ix = get_index_le(matching_traces, timestamp)
        else:
            chronology_label, delay_sign = f'just after {timestamp=}', +1
            closest_stack_trace_ix = get_index_ge(matching_traces, timestamp)
        if closest_stack_trace_ix is None:
            logger.warning(f'No socket operation {chronology_label} has been found for {community_id=}, {direction=}')
            return None
        closest_match: SocketTrace = matching_traces[closest_stack_trace_ix]  # type: ignore
        pos_delta_sec = delay_sign * (closest_match['timestamp'] - timestamp)
        assert pos_delta_sec >= 0, pos_delta_sec
        if pos_delta_sec > self.MAX_DELTA_S:
            logger.warning(
                f'Closest socket operation around {timestamp=} for {community_id=}, {direction=} is too far away ({pos_delta_sec=})'
            )
            return None
        pairing_key = (community_id, direction, closest_stack_trace_ix)
        already_paired_delta_sec = self.paired_socket_traces.get(pairing_key)
        if already_paired_delta_sec is not None:
            raise NotImplementedError(
                f"TODO: find best OVERALL allocations of stacktraces under ({community_id=}, {direction=}) instead of FIFO? "
                f"{pos_delta_sec=}, {already_paired_delta_sec=}, {closest_match['timestamp']=}"
            )
        self.paired_socket_traces[pairing_key] = pos_delta_sec
        logger.debug(f'Stacktrace found with ∆t={pos_delta_sec * 1000:.1f}ms, for {community_id=}, {direction=}')
        return closest_match

    @staticmethod
    def _compact_stack_trace(stack_trace: SocketTraceData) -> list[str]:
        """Compact the stacktrace for convenience"""
        # order of dictionary keys is officially maintained since Python >= 3.7
        return list({call['class']: 0 for call in stack_trace['stack']})

    def _enrich_directed_entry(self, har_entry: dict[str, Any], community_id: CommunityID, direction: FlowDirection) -> None:
        """Attach the stacktrace to the given HAR directed entry (either request or response), in-place"""
        # Fail first
        if direction not in ('in', 'out'):
            raise ValueError(f'Invalid communication direction: {direction}')
        if not self._can_enrich_directed_entry(har_entry):
            return
        # Use read operations on the socket when dealing with a response (in), write operations otherwise
        stack_trace = self._find_best_stacktrace(community_id, direction, Timestamp(har_entry['_timestamp']))
        if stack_trace:  # Attach the stacktrace to the HAR entry if found
            har_entry['_stacktrace'] = {
                'timestamp': stack_trace['timestamp'],
                'process': stack_trace['process'],
                **stack_trace['data'],
                'compact': self._compact_stack_trace(stack_trace['data']),
            }

    def enrich_entry(self, har_entry: dict[str, Any]) -> None:
        """Enrich the HAR data with the stacktraces information"""
        community_id = har_entry.get('_communityId')
        if not community_id:
            return
        self._enrich_directed_entry(har_entry['request'], community_id, direction='out')
        self._enrich_directed_entry(har_entry['response'], community_id, direction='in')
