from __future__ import annotations

import random
import typing
from asyncio import Event
from typing import Dict, List, Tuple, Callable
from ipv8.community import Community, CommunitySettings
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.serialization import Payload
from ipv8.types import Peer, LazyWrappedHandler, MessageHandlerFunction

DataclassPayload = typing.TypeVar('DataclassPayload')
AnyPayload = typing.Union[Payload, DataclassPayload]


def message_wrapper(*payloads: type[AnyPayload]) -> Callable[[LazyWrappedHandler], MessageHandlerFunction]:
    return lazy_wrapper(*payloads)


class Blockchain(Community):
    community_id = b"\x06" * 20

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)
        self.event: Event = None  # type:ignore
        # Register the message handler for messages (with the identifier "1").
        self.nodes: Dict[int, Peer] = {}

    def node_id_from_peer(self, peer: Peer):
        return next((key for key, p in self.nodes.items() if p == peer), None)

    async def started(
            self, node_id: int, connections: List[Tuple[int, int]], event: Event, use_localhost: bool = True
    ) -> None:
        self.event = event
        self.node_id = node_id
        self.connections = connections
        self.on_start_delay = random.uniform(1.0, 3.0)  # Seconds
        host_network = self._get_lan_address()[0]
        host_network_base = ".".join(host_network.split(".")[:3])

        async def _ensure_nodes_connected() -> None:
            # Make connections to known peers
            for node_id, conn in connections:
                ip_address = f"{host_network_base}.{node_id + 10}"
                if use_localhost:
                    ip_address = host_network
                ad = (ip_address, conn)
                self.walk_to(ad)
            valid = False
            conn_nodes = []

            for node_id, node_port in self.connections:
                conn_nodes = [
                    p for p in self.get_peers() if p.address[1] == node_port
                ]
                if len(conn_nodes) == 0:
                    return
                valid = True
                self.nodes[node_id] = conn_nodes[0]
            if not valid:
                return
            self.cancel_pending_task("ensure_nodes_connected")
            print(f'[Node {self.node_id}] Starting')
            self.register_anonymous_task(
                "delayed_start", self.on_start, delay=self.on_start_delay
            )

        self.register_task(
            "ensure_nodes_connected", _ensure_nodes_connected, interval=.5, delay=1
        )

    def on_start(self):
        pass

    def stop(self, delay: int = 0):

        async def delayed_stop():
            print(f"[Node Stopping algorithm")
            self.event.set()

        self.register_anonymous_task('delayed_stop', delayed_stop, delay=delay)

    def ez_send(self, peer: Peer, *payloads: AnyPayload, **kwargs) -> None:
        super().ez_send(peer, *payloads, **kwargs)

    def add_message_handler(self, msg_num: int | type[AnyPayload], callback: MessageHandlerFunction) -> None:
        super().add_message_handler(msg_num, callback)
