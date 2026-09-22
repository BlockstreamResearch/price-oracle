# Contracts specification

# 1\. AuthAsset or Storm Eye contract

## 1.1. Description

This contract is central to the network's authorization process. It enables the secure inclusion of a Storm Eye UTXO in a transaction without changing the Storm Tree root, or the secure update of the Storm Tree root.

## 1.2. Compilation parameters

1. `MAX_SPLIT_UTXOS_COUNT` - the exclusive upper bound on the number of UTXOs a Storm Eye can be split into.
2. `MAX_MERGE_UTXOS_COUNT` - the exclusive upper bound on the number of Storm Eye UTXOs that can be merged.
3. `RESCUE_OUTPUT_SCRIPT_HASH` - the output script hash where the Storm Eye must be sent once the rescue block number is reached.

## 1.3. Taproot storage slots

1. Storm Tree root
2. Rescue block number

The storage is not a witness the spender can choose freely: every path rebuilds the covenant's script hash from the claimed storage and requires it to equal `jet::current_script_hash()`.

### 1.3.1. Script hash for a storage state

`get_script_hash_for_storage(merkle_root, rescue_block_number)` computes:

1. `slot(v)` - the TapData-tagged SHA-256 of a 32-byte value `v`.
    - Slot 0 is `merkle_root` as is.
    - Slot 1 is `rescue_block_number` widened to 32 bytes: 28 zero bytes, then the height as a big-endian `u32`.
2. `tap_root = tapbranch(tapbranch(jet::tapleaf_hash(), slot(merkle_root)), slot(rescue_block_number))`
3. `output_key = taptweak(NUMS, tap_root)`, where `NUMS` is the BIP-341 unspendable internal key `0x50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0`.
4. The result is `sha256(0x5120 || output_key)`: the script hash of the Taproot output.

## 1.4. Spending paths

The Storm Eye contract has the following spending paths:

1. Authorized inclusion in a transaction **without** storage updating.
2. Authorized inclusion in a transaction **with** an update to the Storm Tree root using the network signature.
3. Authorized inclusion in a transaction **with** an update to the rescue block number using a network signature.
4. Authorized splitting of a Storm Eye UTXO into multiple UTXOs with the same Storm Tree root.
5. Authorized merging of multiple Storm Eyes into a single Storm Eye UTXO with the same Storm Tree root.
6. Inclusion in a transaction upon reaching the rescue block number, spending to an output with the `RESCUE_OUTPUT_SCRIPT_HASH` script hash.

### 1.4.0. Witness and network authorization

The witness is a single value:

```
PATH: Either<
    (storage, bloom, path_witness),   // paths 1-5, network-authorized
    (storage, output_index)           // path 6, rescue
>

storage = (merkle_root: u256, rescue_block_number: u32)
bloom   = (signature: Signature, branch: Pubkey, proof: [Either<(), (is_right: bool, sibling: u256)>; 17])
```

For paths 1-5, the network authorization is checked **once, before the paths diverge**:

1. `leaf = sha256(branch || 0x01)`
2. For each proof step: `Left(())` leaves the node unchanged (an unused level); `Right((is_right, sibling))` replaces it with `sha256(sibling || node)` if `is_right`, else `sha256(node || sibling)`.
3. `assert(folded_root == merkle_root)`, where `merkle_root` is the **current** root from `storage`.
4. `message = sha256(tag || tag || jet::sig_all_hash())` with `tag = sha256("OracleNetworkV1/StormEye")`, i.e. the BIP-340 tagged hash.
5. `bip_0340_verify((branch, message), signature)`

`branch` is the MuSig2 key of the signing combination. The per-path witnesses below list only the fields specific to each path.

### 1.4.1. Authorized inclusion in a transaction without updating the Storm Tree root

In this scenario, the Storm Eye UTXO must be spent in its entirety without changing the `script_pubkey`.

The following witness parameters are accepted for spending:

1. `output_index` - the output index that contains the Storm Eye UTXO

This spending path will include the following checks:

1. `assert(jet::current_script_hash() == get_script_hash_for_storage(merkle_root, rescue_block_number))`
2. `assert(jet::output_script_hash(output_index) == jet::current_script_hash())`
3. `assert(jet::output_asset(output_index) == jet::current_asset())`
4. `assert(jet::output_amount(output_index) == jet::current_amount())`

### 1.4.2. Authorized inclusion in a transaction with an update to the Storm Tree root using the network signature

In this scenario, the Storm Eye UTXO must be spent in its entirety, changing the `script_pubkey` to migrate to the new Storm Tree root. The network authorization (1.4.0) is checked against the **current** root.

The following witness parameters are accepted for spending:

1. `new_merkle_root` - the new Storm Tree root
2. `output_index` - the output index that contains the Storm Eye UTXO

This spending path will include the following checks:

1. `assert(jet::current_script_hash() == get_script_hash_for_storage(merkle_root, rescue_block_number))`
2. `assert(jet::output_script_hash(output_index) == get_script_hash_for_storage(new_merkle_root, rescue_block_number))`
3. `assert(jet::output_asset(output_index) == jet::current_asset())`
4. `assert(jet::output_amount(output_index) == jet::current_amount())`

### 1.4.3. Authorized inclusion in a transaction with an update to the rescue block number using a network signature

In this scenario, the Storm Eye UTXO must be spent in its entirety, changing the `script_pubkey` to migrate to the new rescue block number.

The following witness parameters are accepted for spending:

1. `new_rescue_block_number` - the new block number after which the rescue spending path is available
2. `output_index` - the output index that contains the Storm Eye UTXO

This spending path will include the following checks:

1. `assert(new_rescue_block_number == safe_add(rescue_block_number, 1_576_800))` - minutes in 3 years; an overflow fails the spend.
2. `assert(jet::current_script_hash() == get_script_hash_for_storage(merkle_root, rescue_block_number))`
3. `assert(jet::output_script_hash(output_index) == get_script_hash_for_storage(merkle_root, new_rescue_block_number))`
4. `assert(jet::output_asset(output_index) == jet::current_asset())`
5. `assert(jet::output_amount(output_index) == jet::current_amount())`

The new height is 3 years after the **current rescue height**, not after the current block. The covenant does not limit when a renewal may happen; renewing only within the last month before expiry is node policy.

### 1.4.4. Authorized splitting of a Storm Eye UTXO into multiple UTXOs with the same Storm Tree root

In this scenario, Storm Eye is split into N UTXOs, where `1 < N < MAX_SPLIT_UTXOS_COUNT`. The amounts among these N UTXOs are distributed in any way, while retaining the same `script_pubkey`.

The following witness parameters are accepted for spending:

1. `split_utxos_count` - the number of UTXOs into which Storm Eye should be split (`u8`)

This spending path will include the following checks:

1. `assert(jet::current_index() == 0)`
2. `assert(jet::current_script_hash() == get_script_hash_for_storage(merkle_root, rescue_block_number))`
3. `assert(split_utxos_count > 1 && split_utxos_count < param::MAX_SPLIT_UTXOS_COUNT)`
4. for `i in 0..split_utxos_count`:
    1. `total_outputs_amount += jet::output_amount(i)`
    2. `assert(jet::output_script_hash(i) == jet::current_script_hash())`
    3. `assert(jet::output_asset(i) == jet::current_asset())`
5. `assert(jet::current_amount() == total_outputs_amount)`

### 1.4.5. Authorized merging of multiple Storm Eyes into a single Storm Eye UTXO with the same Storm Tree root

In this scenario, N Storm Eye UTXOs at inputs `0..N` are merged into a single Storm Eye UTXO at output 0 with the same Storm Tree root, where `1 < N < MAX_MERGE_UTXOS_COUNT`.

The following witness parameters are accepted for spending:

1. `utxos_to_merge` - the number of Storm Eye UTXOs that must be merged into a single UTXO (`u8`)

This spending path will include the following checks:

1. `assert(jet::current_script_hash() == get_script_hash_for_storage(merkle_root, rescue_block_number))`
2. `assert(jet::output_script_hash(0) == jet::current_script_hash())`
3. `assert(utxos_to_merge > 1 && utxos_to_merge < param::MAX_MERGE_UTXOS_COUNT)`
4. `assert(jet::current_index() < utxos_to_merge)` - the current input must be one of the merged inputs.
5. for `i in 0..utxos_to_merge`:
    1. `total_inputs_amount += jet::input_amount(i)`
    2. `assert(jet::input_script_hash(i) == jet::current_script_hash())`
    3. `assert(jet::input_asset(i) == jet::current_asset())`
6. `assert(jet::output_amount(0) == total_inputs_amount)`
7. `assert(jet::output_asset(0) == jet::current_asset())`

### 1.4.6. Inclusion in a transaction upon reaching the rescue block number

In this scenario, anyone can rescue the Storm Eye UTXO once the rescue block number is reached, spending it to an output with the `param::RESCUE_OUTPUT_SCRIPT_HASH` script hash. No signature and no proof are required.

The following witness parameters are accepted for spending:

1. `storage` - `(merkle_root, rescue_block_number)`
2. `output_index` - the output index that receives the Storm Eye

This spending path will include the following checks:

1. `assert(jet::current_script_hash() == get_script_hash_for_storage(merkle_root, rescue_block_number))`
2. `jet::check_lock_height(rescue_block_number)`
3. `assert(jet::output_script_hash(output_index) == param::RESCUE_OUTPUT_SCRIPT_HASH)`
4. `assert(jet::output_asset(output_index) == jet::current_asset())`
5. `assert(jet::output_amount(output_index) == jet::current_amount())`

## 1.5. Contract creation transaction

In the transaction to create Storm Eye, the whole supply is issued at once, with no reissuance token, straight into the covenant. These conditions must be verified by the network before Storm Eye can be used.

Inputs:

1. A policy asset UTXO carrying the issuance: `issuance_amount = 10000`, `inflation_amount = 0`

Outputs:

1. Six Storm Eye UTXOs splitting the supply of 10000 between them, each under the covenant with the initial storage (the initial Storm Tree root and rescue block number). All of them are explicit (unblinded).
2. An `OP_RETURN` recording the public keys of the initial network members.
3. Change from the input policy asset UTXO
4. Transaction fee

# 2\. Treasury contract

## 2.1. Description

This contract is intended for storing UTXOs owned by the Oracle network. These UTXOs may be used by the network in accordance with the network's rules.

## 2.2. Compilation parameters

1. STORM\_EYE\_ASSET\_ID \- the Storm Eye asset ID that will be used for the network authorization.

## 2.3. Spending paths

The Treasury contract has the following spending paths:

1. Network authorized spending

### 2.3.1. Network authorized spending

In this scenario, the network can spend a Treasury UTXO. To spend it, the network must include the Storm Eye UTXO in the transaction.

The following witness parameters are accepted for spending:

1. *storm\_eye\_input\_index* \- the Storm Eye UTXO input index  

This spending path will include the following checks:

1. assert(jet::input\_asset(*storm\_eye\_input\_index*) \== param::STORM\_EYE\_ASSET\_ID)

# 3\. Voucher contract (Tick and Verifier)

## 3.1. Description

This contract is designed for Tick asset UTXOs, which will store a timestamp in their amount. The same covenant is used for Verifier asset UTXOs, which carry the public key used to verify price data in their Taproot internal key and have an amount of 1. On-chain, only the asset ID tells a Tick from a Verifier. These UTXOs will be issued to users and burned after being used by the user or by the network.

## 3.2. Auth mechanisms

This covenant will support three authorization options that the user can specify in the request to create a voucher. The following authorization options are available:

1. Asset auth \- this method allows you to spend a voucher if an input with the desired Asset ID is added to the transaction.  
2. Script auth \- this method allows you to spend a voucher if an input with the desired script hash is added to the transaction.  
3. Signature auth \- this method allows you to spend a voucher if a valid signature for the *jet::sig\_all\_hash* message is provided in the transaction witness.

The contract supports only one auth method at a time. The network must set the compilation parameters that do not apply to the user-selected auth method to their default values.

## 3.3. Compilation parameters

1. STORM\_EYE\_ASSET\_ID \- the Storm Eye asset ID that will be used for the network burning process.  
2. AUTH\_METHOD \- the index of the auth method.  
3. AUTH\_ASSET\_ID \- the auth asset ID that the user provided in the voucher request  
4. AUTH\_SCRIPT\_HASH \- the auth script hash that the user provided in the voucher request  
5. AUTH\_PUBKEY \- the auth schnorr pubkey that the user provided in the voucher request

## 3.4. Spending paths

The voucher contract has the following spending paths:

1. User spending via the Asset authorization method  
2. User spending via the Script authorization method  
3. User spending via the Signature authorization method  
4. Network authorized spending

The user spending paths burn the voucher into an OP\_RETURN tagged with the voucher's own input index: its first entry must be the pushed data *jet::current\_index()* as 4 big-endian bytes. Input indexes are unique, so two vouchers cannot be burned into the same output.

### 3.4.1. User spending via the Asset authorization method

In this scenario, a user can spend a voucher if they include an input in the transaction that has the *AUTH\_ASSET\_ID* asset ID.

The following witness parameters are accepted for spending:

1. *asset\_auth\_utxo\_input\_index* \- the input index of the Asset auth UTXO  
2. *voucher\_utxo\_output\_index* \- the output index of the burn output

This spending path will include the following checks:

1. assert(param::AUTH\_METHOD \== 0\)  
2. assert(jet::input\_asset(*asset\_auth\_utxo\_input\_index*) \== param::AUTH\_ASSET\_ID)  
3. assert(jet::output\_asset(*voucher\_utxo\_output\_index*) \== jet::current\_asset())  
4. assert(jet::output\_amount(*voucher\_utxo\_output\_index*) \== jet::current\_amount())  
5. assert(jet::output\_null\_datum(*voucher\_utxo\_output\_index*, 0) \== Some(Some(Left((\_, sha256(u32\_be(jet::current\_index())))))))

### 3.4.2. User spending via the Script authorization method

In this scenario, a user can spend a voucher if they include an input in the transaction that has the *AUTH\_SCRIPT\_HASH* script hash.

The following witness parameters are accepted for spending:

1. *script\_auth\_utxo\_input\_index* \- the input index of the Script auth UTXO  
2. *voucher\_utxo\_output\_index* \- the output index of the burn output

This spending path will include the following checks:

1. assert(param::AUTH\_METHOD \== 1\)  
2. assert(jet::input\_script\_hash(*script\_auth\_utxo\_input\_index*) \== param::AUTH\_SCRIPT\_HASH)  
3. assert(jet::output\_asset(*voucher\_utxo\_output\_index*) \== jet::current\_asset())  
4. assert(jet::output\_amount(*voucher\_utxo\_output\_index*) \== jet::current\_amount())  
5. assert(jet::output\_null\_datum(*voucher\_utxo\_output\_index*, 0) \== Some(Some(Left((\_, sha256(u32\_be(jet::current\_index())))))))

### 3.4.3. User spending via the Signature authorization method

In this scenario, a user can spend a voucher if they provide the required signature in the transaction witness.

The following witness parameters are accepted for spending:

1. *auth\_signature* \- the *jet::sig\_all\_hash* auth signature  
2. *voucher\_utxo\_output\_index* \- the output index of the burn output

This spending path will include the following checks:

1. assert(param::AUTH\_METHOD \== 2\)  
2. jet::bip\_0340\_verify((param::AUTH\_PUBKEY, jet::sig\_all\_hash()), *auth\_signature*)  
3. assert(jet::output\_asset(*voucher\_utxo\_output\_index*) \== jet::current\_asset())  
4. assert(jet::output\_amount(*voucher\_utxo\_output\_index*) \== jet::current\_amount())  
5. assert(jet::output\_null\_datum(*voucher\_utxo\_output\_index*, 0) \== Some(Some(Left((\_, sha256(u32\_be(jet::current\_index())))))))

### 3.4.4. Network authorized spending

In this scenario, the network can spend a voucher. To spend it, the network must include the Storm Eye UTXO in the transaction.

The following witness parameter is accepted for spending:

1. *storm\_eye\_input\_index* \- the Storm Eye UTXO input index  

This spending path includes only the following covenant check:

1. assert(jet::input\_asset(*storm\_eye\_input\_index*) \== param::STORM\_EYE\_ASSET\_ID)  

Before signing, every network node validates that all selected voucher amounts are summed exactly into one empty OP\_RETURN output with the voucher asset. This permits many voucher inputs to share one aggregate burn output without relying on an invalid per-input inequality.

## 3.5. Tick creation transaction

To create a Tick asset UTXO, the network must use a Tick asset inflation token. To do this, the network must include a Storm Eye transaction.

Inputs:

1. Storm Eye UTXO  
2. Tick asset inflation token with the *issuance\_amount* set to the needed value and *asset\_entropy* that was used during the initial asset issuance  
3. Policy asset UTXO to cover the transaction fee

Outputs:

1. Storm Eye UTXO  
2. Tick asset inflation token with the same *script\_pubkey* and amount  
3. Tick asset UTXO with the needed amount and the corresponding covenant  
4. Change from the input policy asset UTXOs  
5. Transaction fee

## 3.6. Verifier creation transaction

To create a Verifier asset UTXO, the network must use a Verifier asset inflation token. To do this, the network must include a Storm Eye transaction.

Inputs:

1. Storm Eye UTXO  
2. Verifier asset inflation token with the *issuance\_amount* set to 1 and *asset\_entropy* that was used during the initial asset issuance  
3. Policy asset UTXO to cover the transaction fee

Outputs:

1. Storm Eye UTXO  
2. Verifier asset inflation token with the same *script\_pubkey* and amount  
3. Verifier asset UTXO with the corresponding covenant  
4. Change from the input policy asset UTXOs  
5. Transaction fee

# 4\. Account contract

## 4.1. Description

This contract is designed to store users' LBTC, which will be used by the network to issue and burn Tick and Verifier UTXOs.

## 4.2. Compilation parameters

1. STORM\_EYE\_ASSET\_ID \- the Storm Eye asset ID that will be used for the network authorization.  
2. ACCOUNT\_OWNER\_PUBKEY \- the account owner Schnorr pubkey

## 4.3. Spending paths

The Account contract has the following spending paths:

1. Network authorized spending

### 4.3.1. Network authorized spending

In this scenario, the network can spend a user Account UTXO. To spend it, the network must include the Storm Eye UTXO in the transaction.

The following witness parameters are accepted for spending:

1. *storm\_eye\_input\_index* \- the Storm Eye UTXO input index  

This spending path will include the following checks:

1. assert(jet::input\_asset(*storm\_eye\_input\_index*) \== param::STORM\_EYE\_ASSET\_ID)  
