# Price Oracle

This is the repository where the main development effort of the price oracle running on Liquid will take place.

## Specification

The specification lives in [specs](./specs):

- [Oracle network architecture](./specs/oracle-network-architecture.md): network topology, leader and coordinator roles, the Storm messaging protocol, MuSig2 signing over the Storm Tree, the Storm Eye authorization asset, treasury and user accounts, network-issued Tick and Oracle Verifier UTXOs, node state, and security considerations.
- [Contracts specification](./specs/contracts-specification.md): the Simplicity contracts behind it — the Storm Eye (AuthAsset), Treasury, Voucher (Tick and Verifier) and Account contracts.
