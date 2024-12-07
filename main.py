from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8.util import run_forever
from ipv8_service import IPv8
from asyncio import run

from my_community import MyCommunity
from validator_community import ValidatorCommunity

from validator_community import ValidatorCommunity

import argparse


async def start_communities(node_id) -> None:
    """ Initialize IPv8 and start the communities. """
    
    
    builder = ConfigBuilder().clear_keys().clear_overlays()
    builder.add_key("my peer", "medium", f"ec1.pem")
    
    builder.add_overlay("MyCommunity", "my peer",
                        [WalkerDefinition(Strategy.RandomWalk,
                                          20, {'timeout': 3.0})],
                        default_bootstrap_defs, {}, [('started',)])
    
    builder.add_overlay("ValidatorCommunity", "my peer",
                        [WalkerDefinition(Strategy.RandomWalk,
                                          20, {'timeout': 3.0})],
                        default_bootstrap_defs, {}, [('started', node_id)])
    
    
    
    await IPv8(builder.finalize(), extra_communities={'MyCommunity': MyCommunity, 'ValidatorCommunity': ValidatorCommunity}).start()
    await run_forever()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="Blockchain",
        description="Code to execute blockchain.",
        epilog="Designed for A27 Fundamentals and Design of Blockchain-based Systems",
    )
    parser.add_argument("node_id", type=int)
    parser.add_argument("topology", type=str, nargs="?", default="topologies/default.yaml")
    parser.add_argument("algorithm", type=str, nargs="?", default='echo')
    parser.add_argument("-docker", action='store_true')

    args = parser.parse_args()
    node_id = args.node_id
    
        
        
    run(start_communities(node_id))