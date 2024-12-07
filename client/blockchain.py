class Blockchain:
    def __init__(self):
        self.chain = []

    def add_block(self, block):
        self.chain.append(block)

    def get_last_block(self):
        return self.chain[-1] if self.chain else None

    def is_valid_chain(self, chain):
        for i in range(1, len(chain)):
            current_block = chain[i]
            previous_block = chain[i - 1]
            if current_block.previous_block_hash != previous_block.compute_hash():
                return False
            if not self.is_valid_proof(current_block):
                return False
        return True

    def is_valid_proof(self, block):
        target_prefix = '0' * block.difficulty_target
        return block.compute_hash().startswith(target_prefix)

    def resolve_conflicts(self, new_chain):
        if len(new_chain) > len(self.chain):
            if self.is_valid_chain(new_chain):
                self.chain = new_chain
                return True
        elif len(new_chain) == len(self.chain):
            if self.is_valid_chain(new_chain):
                if new_chain[-1].ts < self.chain[-1].ts:
                    self.chain = new_chain
                    return True
        return False
