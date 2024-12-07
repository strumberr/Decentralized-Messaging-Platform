from hashlib import sha256

class MerkleTree:
    """ Implementation of a Merkle Tree for storing message hashes. """

    def __init__(self):
        self.leaves = []
        self.levels = []

    def add_leaf(self, data, do_hash=True):
        """ Add a leaf to the Merkle Tree, optionally hashing the data. """
        if do_hash:
            data = sha256(data.encode('utf-8')).hexdigest()
        self.leaves.append(data)
        self.build_tree()

    def build_tree(self):
        """ Build the Merkle Tree from the leaves. """
        self.levels = [self.leaves]
        current_level = self.leaves
        while len(current_level) > 1:
            new_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                new_level.append(sha256((left + right).encode('utf-8')).hexdigest())
            current_level = new_level
            self.levels.append(current_level)

    def get_root(self):
        """ Get the root hash of the Merkle Tree. """
        if self.levels:
            return self.levels[-1][0]
        return None
