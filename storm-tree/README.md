# Storm Tree

`storm-tree` constructs the Storm Tree described by the Oracle Network
specification. It commits to every minimum-threshold subset of network nodes by
placing that subset's MuSig2 aggregate X-only public key in a SHA-256 sparse
Merkle tree.

The crate uses the MuSig2 implementation from the pinned
`rust-secp256k1` 0.32 beta release.

## Construction

`StormTree::new` accepts serialized 32-byte X-only secp256k1 public keys. It:

1. Validates every public key.
2. Sorts keys lexicographically and rejects duplicates.
3. Computes the threshold as two-thirds of the node count, rounded up.
4. Enumerates each threshold-sized subset exactly once.
5. Aggregates each subset with MuSig2 in canonical key order.
6. Inserts each aggregate key as both key and leaf in a SHA-256 sparse Merkle tree.

Combinations are sets, not permutations. For example, `[Node1, Node2, Node3]`
and `[Node1, Node3, Node2]` describe the same subset and produce one branch.

| Nodes | Threshold |
| ---: | ---: |
| 3 | 2 |
| 4 | 3 |
| 5 | 4 |
| 6 | 4 |

## Example

```rust
use secp256k1::{Keypair, SecretKey, XOnlyPublicKey};
use storm_tree::StormTree;

fn node_key(seed: u8) -> [u8; 32] {
    let secret_key = SecretKey::from_secret_bytes([seed; 32]).unwrap();
    let keypair = Keypair::from_secret_key(&secret_key);
    XOnlyPublicKey::from_keypair(&keypair).0.serialize()
}

let nodes = vec![node_key(1), node_key(2), node_key(3)];
let mut tree = StormTree::new(nodes).unwrap();

assert_eq!(tree.threshold(), 2);
assert_eq!(tree.branches().len(), 3);

let branch = tree.branches().next().unwrap();
let participants = tree.nodes_for_branch(&branch).unwrap();
assert_eq!(participants.len(), 2);

let proof = tree.proof(&branch).unwrap();
assert!(StormTree::verify_branch(&tree.root(), &branch, &proof));
```

## Security Properties

- Node identity keys must be valid, unique X-only secp256k1 keys.
- X-only keys are lifted with even parity, then aggregated in lexicographic order.
  This gives every node the same MuSig2 aggregate key for the same participant set.
- Distinct participant sets producing the same aggregate key are rejected. Such a
  collision is not expected without breaking the underlying cryptographic assumptions.
- Sparse Merkle internal nodes use SHA-256. A proof authenticates an aggregate
  branch key against a root; it does not establish that the root itself is trusted.
- Initialization is combinatorial. Construction rejects participant sets that
  exceed 100,000 branches, limiting accidental or adversarial CPU and memory use.
- Secret keys, nonce generation, partial signatures, and signature aggregation are
  outside this crate. MuSig2 signers must independently follow the nonce-handling
  requirements of `rust-secp256k1`.

The reverse branch lookup is local metadata. On-chain verification only needs the
aggregate branch key, its inclusion proof, and an authoritative Storm Tree root.
