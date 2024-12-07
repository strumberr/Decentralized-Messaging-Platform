from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from base64 import b64encode, b64decode
import json
import random
import time
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8.util import run_forever
from ipv8_service import IPv8
from asyncio import run, sleep
from ipv8.community import Community, CommunitySettings, lazy_wrapper
from ipv8.types import Peer
from transaction import Transaction, SignedTransaction
from dataclasses import dataclass, field
from typing import List
from ipv8.messaging.payload_dataclass import overwrite_dataclass
from json.decoder import JSONDecodeError


builder = ConfigBuilder().clear_keys().clear_overlays()
dataclass = overwrite_dataclass(dataclass)


class bcolors:
    SENDTRANSACTION = "\033[94m"
    ERROR = "\033[91m"


@dataclass(msg_id=69)
class RequestBlock:
    blockchain: str 


@dataclass(msg_id=70)
class ResponseBlock:
    blockchain: str 


class MyCommunity(Community):
    community_id = b"harbourspaceuniverse"

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)
        self.blockchain = []  # This should be initialized with your blockchain data
        self.received_blocks = []
        self.add_message_handler(ResponseBlock, self.on_block_response)
        self.counter = 0
        self.chainbane = []

    def started(self) -> None:
        self.register_task(
            "retrieve_blocks_from_all_peers", self.retrieve_blocks_from_all_peers, interval=1.0, delay=3.0
        )

    async def request_blocks(self, peer: Peer) -> None:
        self.ez_send(peer, RequestBlock(blockchain=""))

    @lazy_wrapper(RequestBlock)
    async def on_block_request(self, peer: Peer, payload: RequestBlock) -> None:
        # Convert the blockchain to JSON string before sending
        blockchain_json = json.dumps([block.__dict__ for block in self.blockchain])
        self.ez_send(peer, ResponseBlock(blockchain=blockchain_json))


    @lazy_wrapper(ResponseBlock)
    async def on_block_response(self, peer: Peer, payload: ResponseBlock) -> None:
        # Print the raw payload for debugging purposes
        print(f"Raw blocks: {payload.blockchain}")
        
        payload_json = payload.blockchain

        cleaned_json_str = payload_json.replace('\\n', '').replace('\\"', '"').replace('\\\\', '\\').replace('"{', '{').replace('}"', '}')

        # Step 2: Parse the main JSON string
        parsed_data = json.loads(cleaned_json_str)

        self.chainbane.append(parsed_data)
        
        # check if block is already in the list
        if parsed_data not in self.received_blocks:
            self.received_blocks.append(parsed_data)
            
            with open(f'blocks{self.counter}.txt', 'w') as f:
                json.dump(parsed_data, f, indent=4)
            
        
        
        self.counter += 1
            


    async def retrieve_blocks_from_all_peers(self) -> None:
        peers = self.get_peers()
        # print all the peers
        print(peers)
        for peer in peers:
            await self.request_blocks(peer)
            await sleep(1)  # Sleep to give time for responses


        # Save the aggregated blocks to a JSON file
        with open('blocks.json', 'w') as f:
            json.dump(self.received_blocks, f, indent=4)
        print("Blocks saved to blocks.json")


async def start_communities() -> None:
    builder.add_key("my peer", "medium", f"ec1.pem")

    builder.add_overlay("MyCommunity", "my peer",
                        [WalkerDefinition(Strategy.RandomWalk,
                                          20, {'timeout': 1.0})],
                        default_bootstrap_defs, {}, [('started',)])

    ipv8 = IPv8(builder.finalize(), extra_communities={'MyCommunity': MyCommunity})

    await ipv8.start()
    await sleep(5)

    # Manually call the retrieve_blocks_from_all_peers method
    # community = ipv8.overlays[MyCommunity.community_id][0]
    # await community.retrieve_blocks_from_all_peers()

    await ipv8.stop()


# Run the function with no arguments to start the community and retrieve blocks
run(start_communities())
