# Contracts specification

# 1\. AuthAsset or Storm Eye contract

## 1.1. Description

This contract is central to the network's authorization process. It enables the secure inclusion of a Storm Eye UTXO in a transaction without changing the Storm Tree root, or the secure update of the Storm Tree root.

## 1.2. Compilation parameters

1. *MAX\_SPLIT\_UTXOS\_COUNT* \- the maximum number of UTXOs into which Storm Eye can be split.  
2. *MAX\_MERGE\_UTXOS\_COUNT* \- the maximum number of Storm Eye UTXOs that can be merged.  
3. *RESCUE\_OUTPUT\_SCRIPT\_HASH* \- the output script hash, where tokens should be sent after rescue block number is reached

## 1.3. Taproot storage slots

1. Storm Tree root  
2. Rescue block number

## 1.4. Spending paths

The Storm Eye contract has next spending paths:

1. Authorized inclusion in a transaction **without** storage updating.  
2. Authorized inclusion in a transaction **with** an update to the Storm Tree root using the network signature.  
3. Authorized inclusion in a transaction **with** an update to the rescue block number using a network signature.  
4. Authorized splitting of a Storm Eye UTXO into multiple UTXOs with the same Storm Tree root.  
5. Authorized merging of multiple Storm Eyes into a single Storm Eye UTXO with the same Storm Tree root.  
6. Inclusion in a transaction upon reaching the rescue block number, with the option to spend to output with the *RESCUE\_OUTPUT\_SCRIPT\_HASH* script hash.

### 1.4.1. Authorized inclusion in a transaction without updating the Storm Tree root

In this scenario, the Storm Eye UTXO must be spent in its entirety without changing the *script\_pubkey*. To spend it, the network must provide a signature and a Storm Tree Proof.

The following witness parameters are accepted for spending:

1. *merkle\_root* \- Storm Tree root, which is required to build Taproot storage  
2. *rescue\_block\_number* \- the block number after which the rescue spending path is available  
3. *output\_index* \- the output index that contains the Storm Eye UTXO  
4. *signature* \- the network signature  
5. *merkle\_proof* \- Storm Merkle proof for getting and verifying a Storm Merkle bloom  
6. *storm\_tree\_bloom* \- Storm Merkle tree leaf to prove

This spending path will include the following checks:

1. expected\_script\_hash \= get\_script\_hash\_for\_storage(*merkle\_root, rescue\_block\_number*)  
2. assert(jet::current\_script\_hash() \== expected\_script\_hash)  
3. assert(jet::output\_script\_hash(*output\_index*) \== expected\_script\_hash)  
4. assert(jet::output\_asset(*output\_index*) \== jet::current\_asset())  
5. assert(jet::output\_amount(*output\_index*) \== jet::current\_amount())  
6. verify\_merkle\_proof(*merkle\_root*, *merkle\_proof, storm\_tree\_bloom*)  
7. bip\_0340\_verify(storm\_tree\_bloom, *signature*, jet::sig\_all\_hash())

### 1.4.2. Authorized inclusion in a transaction with an update to the Storm Tree root using the network signature

In this scenario, the Storm Eye UTXO must be spent in its entirety with the changing of the *script\_pubkey* to migrate to the new Storm Tree root. To spend it, the network must provide a signature and a Storm Tree Proof.

The following witness parameters are accepted for spending:

1. *current\_merkle\_root* \- the current Storm Tree root, which is required to build the current Taproot storage  
2. new\_merkle\_root \- the new Storm Tree root, which is required to build the new Storm Eye UTXO *script\_pubkey*  
3. *rescue\_block\_number* \- the block number after which the rescue spending path is available  
4. *output\_index* \- the output index that contains the Storm Eye UTXO  
5. *signature* \- the network signature  
6. *merkle\_proof* \- Storm Merkle proof for getting and verifying a Storm Merkle bloom  
7. *storm\_tree\_bloom* \- Storm Merkle tree leaf to proof

This spending path will include the following checks:

1. expected\_current\_script\_hash \= get\_script\_hash\_for\_storage(*current\_merkle\_root, rescue\_block\_number*)  
2. expected\_new\_script\_hash \= get\_script\_hash\_for\_storage(*new\_merkle\_root, rescue\_block\_number*)  
3. assert(jet::current\_script\_hash() \== expected\_current\_script\_hash)  
4. assert(jet::output\_script\_hash(*output\_index*) \== expected\_new\_script\_hash)  
5. assert(jet::output\_asset(*output\_index*) \== jet::current\_asset())  
6. assert(jet::output\_amount(*output\_index*) \== jet::current\_amount())  
7. assert(*storm\_tree\_bloom* \== verify\_merkle\_proof(*merkle\_root*, *merkle\_proof*))  
8. bip\_0340\_verify(storm\_tree\_bloom, *signature*, jet::sig\_all\_hash())

### 1.4.3. Authorized inclusion in a transaction with an update to the rescue block number using a network signature

In this scenario, the Storm Eye UTXO must be spent in its entirety with the changing of the *script\_pubkey* to migrate to the new rescue block number. To spend it, the network must provide a signature and a Storm Tree Proof.

The following witness parameters are accepted for spending:

1. *merkle\_root* \- Storm Tree root, which is required to build Taproot storage  
2. *current\_rescue\_block\_number* \- the current block number after which the rescue spending path is available  
3. new\_rescue\_block\_number \- the new block number after which the rescue spending path is available  
4. *output\_index* \- the output index that contains the Storm Eye UTXO  
5. *signature* \- the network signature  
6. *merkle\_proof* \- Storm Merkle proof for getting and verifying a Storm Merkle bloom  
7. *storm\_tree\_bloom* \- Storm Merkle tree leaf to proof

This spending path will include the following checks:

1. expected\_new\_rescue\_block\_number \= *current\_rescue\_block\_number* \+ 1 576 800 // minutes in 3 years  
2. assert(new\_rescue\_block\_number \== expected\_new\_rescue\_block\_number)  
3. expected\_current\_script\_hash \= get\_script\_hash\_for\_storage(*merkle\_root, current\_rescue\_block\_number*)  
4. expected\_new\_script\_hash \= get\_script\_hash\_for\_storage(*merkle\_root, new\_rescue\_block\_number*)  
5. assert(jet::current\_script\_hash() \== expected\_current\_script\_hash)  
6. assert(jet::output\_script\_hash(*output\_index*) \== expected\_new\_script\_hash)  
7. assert(jet::output\_asset(*output\_index*) \== jet::current\_asset())  
8. assert(jet::output\_amount(*output\_index*) \== jet::current\_amount())  
9. assert(*storm\_tree\_bloom* \== verify\_merkle\_proof(*merkle\_root*, *merkle\_proof*))  
10. bip\_0340\_verify(storm\_tree\_bloom, *signature*, jet::sig\_all\_hash())

### 1.4.4. Authorized splitting of a Storm Eye UTXO into multiple UTXOs with the same Storm Tree root

In this scenario, Storm Eye is split into N UTXOs, where N is greater than 1 and less than *MAX\_SPLIT\_UTXOS\_COUNT*. The amounts among these N UTXOs are distributed in any way, while retaining the same *script\_pubkey*. To spend it, the network must provide a signature and a Storm Tree Proof.

The following witness parameters are accepted for spending:

1. *merkle\_root* \- Storm Tree root, which is required to build Taproot storage  
2. *rescue\_block\_number* \- the block number after which the rescue spending path is available  
3. *split\_utxos\_count* \- the number of UTXOs into which Storm Eye should be split  
4. *signature* \- the network signature  
5. *merkle\_proof* \- Storm Merkle proof for getting and verifying a Storm Merkle bloom  
6. *storm\_tree\_bloom* \- Storm Merkle tree leaf to proof

This spending path will include the following checks:

1. assert(jet::current\_index() \== 0\)  
2. expected\_current\_script\_hash \= get\_script\_hash\_for\_storage(*merkle\_root, rescue\_block\_number*)  
3. assert(jet::current\_script\_hash() \== expected\_script\_hash)  
4. assert(*storm\_tree\_bloom* \== verify\_merkle\_proof(*merkle\_root*, *merkle\_proof*))  
5. bip\_0340\_verify(storm\_tree\_bloom, *signature*, jet::sig\_all\_hash())  
6. assert(*split\_utxos\_count \> 1 && split\_utxos\_count \<* param::MAX\_SPLIT\_UTXOS\_COUNT)  
7. for i in 0..*split\_utxos\_count*  
   1. *total\_outputs\_amount \+= jet::output\_amount(i)*  
   2. assert(jet::output\_script\_hash(i) \== expected\_current\_script\_hash)  
   3. assert(jet::output\_asset(i) \== jet::current\_asset())  
8. assert(jet::current\_amount() \== *total\_outputs\_amount*)

### 1.4.5. Authorized merging of multiple Storm Eyes into a single Storm Eye UTXO with the same Storm Tree root

In this scenario, N Storm Eye UTXOs are merged into a single Storm Eye UTXO with the same Storm Merkle Tree, where N is greater than 1 and less than *MAX\_MERGE\_UTXOS\_COUNT*. To spend it, the network must provide a signature and a Storm Tree Proof.

The following witness parameters are accepted for spending:

1. *merkle\_root* \- Storm Tree root, which is required to build Taproot storage  
2. *rescue\_block\_number* \- the block number after which the rescue spending path is available  
3. *utxos\_to\_merge* \- the number of Storm Eye UTXOs that must be merged into a single UTXO  
4. *signature* \- the network signature  
5. *merkle\_proof* \- Storm Merkle proof for getting and verifying a Storm Merkle bloom  
6. *storm\_tree\_bloom* \- Storm Merkle tree leaf to proof

This spending path will include the following checks:

1. expected\_current\_script\_hash \= get\_script\_hash\_for\_storage(*merkle\_root, rescue\_block\_number*)  
2. assert(jet::current\_script\_hash() \== expected\_script\_hash)  
3. assert(*storm\_tree\_bloom* \== verify\_merkle\_proof(*merkle\_root*, *merkle\_proof*))  
4. bip\_0340\_verify(storm\_tree\_bloom, *signature*, jet::sig\_all\_hash())  
5. assert(*utxos\_to\_merge \> 1 && utxos\_to\_merge \<* param::MAX\_MERGE\_UTXOS\_COUNT)  
6. for i in 0..*utxos\_to\_merge*  
   1. *total\_inputs\_amount \+= jet::input\_amount(i)*  
   2. assert(jet::input\_script\_hash(i) \== expected\_current\_script\_hash)  
   3. assert(jet::input\_asset(i) \== jet::current\_asset())  
7. assert(jet::output\_amount(0) \== *total\_inputs\_amount*)  
8. assert(jet::output\_asset(0) \== jet::current\_asset())  
9. assert(jet::output\_script\_hash(0) \== expected\_current\_script\_hash)

### 1.4.6. Inclusion in a transaction upon reaching the rescue block number

In this scenario, anyone can rescue the StormEye UTXO after the rescue block number is reached and spend it on an output with the param::RESCUE\_OUTPUT\_SCRIPT\_HASH script hash.

The following witness parameters are accepted for spending:

1. *merkle\_root* \- Storm Tree root, which is required to build Taproot storage  
2. *rescue\_block\_number* \- the block number after which the rescue spending path is available  
3. *output\_index* \- the output index that contains the Storm Eye UTXO

This spending path will include the following checks:

1. expected\_script\_hash \= get\_script\_hash\_for\_storage(*merkle\_root, rescue\_block\_number*)  
2. assert(jet::current\_script\_hash() \== expected\_script\_hash)  
3. jet::check\_lock\_height(*rescue\_block\_number*)  
4. assert(jet::output\_script\_hash(*output\_index*) \== param::RESCUE\_OUTPUT\_SCRIPT\_HASH)  
5. assert(jet::output\_asset(*output\_index*) \== jet::current\_asset())  
6. assert(jet::output\_amount(*output\_index*) \== jet::current\_amount())

## 1.5. Contract creation transaction

In the transaction to create Storm Eye, the maximum number of new assets must be issued without reissuing tokens with the corresponding covenant. These conditions must be verified by the network before Storm Eye can be used.

Inputs:

1. A policy asset UTXO with the issuance\_amount set to *10000* and inflation\_amount set to 0

Outputs:

1. A Storm Eye UTXO with the amount of *10000* and the corresponding covenant  
2. Change from the input policy asset UTXO  
3. Transaction fee

# 2\. Tick and Verifier inflation tokens contract

## 2.1. Description

This contract is intended for Tick and Verifier inflation token UTXOs, specifically so that only the protocol can issue Tick and Verifier assets.

## 2.2. Compilation parameters

1. STORM\_EYE\_ASSET\_ID \- the Storm Eye asset ID that will be used for authorized asset issuance.

## 2.3. Spending paths

The Tick and Verifier inflation tokens contract has next spending paths:

1. Asset issuance authorized via Storm Eye

### 2.3.1. Asset issuance authorized via Storm Eye

In this scenario, the issuance of additional assets is permitted if the transaction includes a Storm Eye UTXO; however, the amount and *script\_pubkey* of inflation tokens must not change.

The following witness parameters are accepted for spending:

1. *storm\_eye\_input\_index \-* the input index of the Storm Eye UTXO  
2. *inflation\_token\_output\_index \-* the output index of the inflation token UTXO

This spending path will include the following checks:

1. assert(jet::input\_asset(*storm\_eye\_input\_index*) \== param::STORM\_EYE\_ASSET\_ID)  
2. assert(jet::current\_asset() \== output\_asset(*inflation\_token\_output\_index*))  
3. assert(jet::current\_amount() \== output\_amount(*inflation\_token\_output\_index*))  
4. assert(jet::current\_script\_hash() \== output\_script\_hash(*inflation\_token\_output\_index*))  
5. assert(get\_reissuance\_amount(jet::current\_index()) \> 0\)

## 2.4. Contract creation transaction

In the transaction to create Tick and Verifier inflation tokens, you must set *issuance\_amount* to 0, *inflation\_amount* to 1, and use the appropriate covenant for inflation tokens. These conditions must be verified by the network before the Tick and Verifier inflation tokens can be used.

Inputs:

1. A policy asset UTXO with the issuance\_amount set to 0 and inflation\_amount set to 1  
2. A policy asset UTXO with the issuance\_amount set to 0 and inflation\_amount set to 1

Outputs:

1. A Tick inflation token UTXO with the amount of 1 and the corresponding covenant  
2. A Verifier inflation token UTXO with the amount of 1 and the corresponding covenant  
3. Change from the input policy asset UTXOs  
4. Transaction fee

# 3\. Tick asset contract

## 3.1. Description

This contract is designed for Tick asset UTXOs, which will store a timestamp in their amount. These UTXOs will be issued to users and burned after being used by the user or by the network.

## 3.2. Auth mechanisms

This covenant will support three authorization options that the user can specify in the request to create a Tick UTXO. The following authorization options are available:

1. Asset auth \- this method allows you to spend a Tick UTXO if an input with the desired Asset ID is added to the transaction.  
2. Script auth \- this method allows you to spend a Tick UTXO if an input with the desired script hash is added to the transaction.  
3. Signature auth \- this method allows you to spend a Tick UTXO if a valid signature for the *jet::sig\_all\_hash* message is provided in the transaction witness.

The contract supports only one auth method at a time. The network must set the compilation parameters that do not apply to the user-selected auth method to their default values.

## 3.3. Compilation parameters

1. STORM\_EYE\_ASSET\_ID \- the Storm Eye asset ID that will be used for the network burning process.  
2. AUTH\_METHOD \- the index of the auth method.  
3. AUTH\_ASSET\_ID \- the auth asset ID that the user provided in the Tick UTXO request  
4. AUTH\_SCRIPT\_HASH \- the auth script hash that the user provided in the Tick UTXO request  
5. AUTH\_PUBKEY \- the auth schnorr pubkey that the user provided in the Tick UTXO request

## 3.4. Spending paths

The Tick asset contract has next spending paths:

1. User spending via the Asset authorization method  
2. User spending via the Script authorization method  
3. User spending via the Signature authorization method  
4. Network authorized spending

### 3.4.1. User spending via the Asset authorization method

In this scenario, a user can spend a Tick UTXO if they include an input in the transaction that has the *AUTH\_ASSET\_ID* asset ID.

The following witness parameters are accepted for spending:

1. *asset\_auth\_utxo\_input\_index* \- the input index of the Asset auth UTXO  
2. *tick\_utxo\_output\_index* \- the output index of the Tick UTXO

This spending path will include the following checks:

1. assert(param::AUTH\_METHOD \== 0\)  
2. assert(jet::input\_asset(*asset\_auth\_utxo\_input\_index*) \== param::AUTH\_ASSET\_ID)  
3. assert(jet::output\_asset(*tick\_utxo\_output\_index*) \== jet::current\_asset())  
4. assert(jet::output\_amount(*tick\_utxo\_output\_index*) \== jet::current\_amount())  
5. assert(is\_op\_return(*tick\_utxo\_output\_index*))

### 3.4.2. User spending via the Script authorization method

In this scenario, a user can spend a Tick UTXO if they include an input in the transaction that has the *AUTH\_SCRIPT\_HASH* script hash.

The following witness parameters are accepted for spending:

1. *script\_auth\_utxo\_input\_index* \- the input index of the Script auth UTXO  
2. *tick\_utxo\_output\_index* \- the output index of the Tick UTXO

This spending path will include the following checks:

1. assert(param::AUTH\_METHOD \== 1\)  
2. assert(jet::input\_script\_hash(*script\_auth\_utxo\_input\_index*) \== param::AUTH\_SCRIPT\_HASH)  
3. assert(jet::output\_asset(*tick\_utxo\_output\_index*) \== jet::current\_asset())  
4. assert(jet::output\_amount(*tick\_utxo\_output\_index*) \== jet::current\_amount())  
5. assert(is\_op\_return(*tick\_utxo\_output\_index*))

### 3.4.3. User spending via the Signature authorization method

In this scenario, a user can spend a Tick UTXO if they provided the required signature in the transaction witness.

The following witness parameters are accepted for spending:

1. *auth\_signature \-* the *jet::sig\_all\_hash* auth signature  
2. *tick\_utxo\_output\_index* \- the output index of the Tick UTXO

This spending path will include the following checks:

1. assert(param::AUTH\_METHOD \== 2\)  
2. jet::bip\_0340\_verify((param::AUTH\_PUBKEY, jet::sig\_all\_hash()), *auth\_signature*)  
3. assert(jet::output\_asset(*tick\_utxo\_output\_index*) \== jet::current\_asset())  
4. assert(jet::output\_amount(*tick\_utxo\_output\_index*) \== jet::current\_amount())  
5. assert(is\_op\_return(*tick\_utxo\_output\_index*))

### 3.4.4. Network authorized spending

In this scenario, the network can spend a Tick UTXO. To spend it, the network must include the Storm Eye UTXO in the transaction.

The following witness parameters are accepted for spending:

1. *storm\_eye\_input\_index* \- the Storm Eye UTXO input index  
2. *tick\_utxo\_output\_index* \- the output index of the Tick UTXO

This spending path will include the following checks:

1. assert(jet::input\_asset(*storm\_eye\_input\_index*) \== param::STORM\_EYE\_ASSET\_ID)  
2. assert(jet::output\_asset(*tick\_utxo\_output\_index*) \== jet::current\_asset())  
3. assert(jet::output\_amount(*tick\_utxo\_output\_index*) \== jet::current\_amount())  
4. assert(is\_op\_return(*tick\_utxo\_output\_index*))

## 3.5. Contract creation transaction

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

# 4\. Verifier asset contract

## 4.1. Description

This contract is designed for the Verifier asset UTXOs, which will be used to verify information about asset prices. These UTXOs will be issued to users and burned after being used by the user or by the network.

## 4.2. Auth mechanisms

This covenant will support three authorization options that the user can specify in the request to create a Verifier UTXO. The following authorization options are available:

1. Asset auth \- this method allows you to spend a Verifier UTXO if an input with the desired Asset ID is added to the transaction.  
2. Script auth \- this method allows you to spend a Verifier UTXO if an input with the desired script hash is added to the transaction.  
3. Signature auth \- this method allows you to spend a Verifier UTXO if a valid signature for the *jet::sig\_all\_hash* message is provided in the transaction witness.

Contract supports only one auth method at a time. The network must set the compilation parameters that do not apply to the user-selected auth method to their default values.

## 4.3. Compilation parameters

1. STORM\_EYE\_ASSET\_ID \- the Storm Eye asset ID that will be used for the network burning process.  
2. AUTH\_METHOD \- the index of the auth method.  
3. AUTH\_ASSET\_ID \- the auth asset ID that the user provided in the Verifier UTXO request  
4. AUTH\_SCRIPT\_HASH \- the auth script hash that the user provided in the Verifier UTXO request  
5. AUTH\_PUBKEY \- the auth schnorr pubkey that the user provided in the Verifier UTXO request

## 4.4. Spending paths

The Verifier asset contract has next spending paths:

1. User spending via the Asset authorization method  
2. User spending via the Script authorization method  
3. User spending via the Signature authorization method  
4. Network authorized spending

### 4.4.1. User spending via the Asset authorization method

In this scenario, a user can spend a Verifier UTXO if they include an input in the transaction that has the *AUTH\_ASSET\_ID* asset ID.

The following witness parameters are accepted for spending:

1. *asset\_auth\_utxo\_input\_index* \- the input index of the Asset auth UTXO  
2. *verifier\_utxo\_output\_index* \- the output index of the Verifier UTXO

This spending path will include the following checks:

1. assert(param::AUTH\_METHOD \== 0\)  
2. assert(jet::input\_asset(*asset\_auth\_utxo\_input\_index*) \== param::AUTH\_ASSET\_ID)  
3. assert(jet::output\_asset(*verifier\_utxo\_output\_index*) \== jet::current\_asset())  
4. assert(jet::output\_amount(*verifier\_utxo\_output\_index*) \== jet::current\_amount())  
5. assert(is\_op\_return(*verifier\_utxo\_output\_index*))

### 4.4.2. User spending via the Script authorization method

In this scenario, a user can spend a Verifier UTXO if they include an input in the transaction that has the *AUTH\_SCRIPT\_HASH* script hash.

The following witness parameters are accepted for spending:

1. *script\_auth\_utxo\_input\_index* \- the input index of the Script auth UTXO  
2. *verifier\_utxo\_output\_index* \- the output index of the Verifier UTXO

This spending path will include the following checks:

1. assert(param::AUTH\_METHOD \== 1\)  
2. assert(jet::input\_script\_hash(*script\_auth\_utxo\_input\_index*) \== param::AUTH\_SCRIPT\_HASH)  
3. assert(jet::output\_asset(*verifier\_utxo\_output\_index*) \== jet::current\_asset())  
4. assert(jet::output\_amount(*verifier\_utxo\_output\_index*) \== jet::current\_amount())  
5. assert(is\_op\_return(*verifier\_utxo\_output\_index*))

### 4.4.3. User spending via the Signature authorization method

In this scenario, a user can spend a Verifier UTXO if they provided the required signature in the transaction witness.

The following witness parameters are accepted for spending:

1. *auth\_signature \-* the *jet::sig\_all\_hash* auth signature  
2. *verifier\_utxo\_output\_index* \- the output index of the Verifier UTXO

This spending path will include the following checks:

1. assert(param::AUTH\_METHOD \== 2\)  
2. jet::bip\_0340\_verify((param::AUTH\_PUBKEY, jet::sig\_all\_hash()), *auth\_signature*)  
3. assert(jet::output\_asset(*verifier\_utxo\_output\_index*) \== jet::current\_asset())  
4. assert(jet::output\_amount(*verifier\_utxo\_output\_index*) \== jet::current\_amount())  
5. assert(is\_op\_return(*verifier\_utxo\_output\_index*))

### 4.4.4. Network authorized spending

In this scenario, the network can spend a Verifier UTXO. To spend it, the network must include the Storm Eye UTXO in the transaction.

The following witness parameters are accepted for spending:

1. *storm\_eye\_input\_index* \- the Storm Eye UTXO input index  
2. *verifier\_utxo\_output\_index* \- the output index of the Verifier UTXO

This spending path will include the following checks:

1. assert(jet::input\_asset(*storm\_eye\_input\_index*) \== param::STORM\_EYE\_ASSET\_ID)  
2. assert(jet::output\_asset(*verifier\_utxo\_output\_index*) \== jet::current\_asset())  
3. assert(jet::output\_amount(*verifier\_utxo\_output\_index*) \== jet::current\_amount())  
4. assert(is\_op\_return(*verifier\_utxo\_output\_index*))

## 4.5. Contract creation transaction

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

# 5\. Account contract

## 5.1. Description

This contract is designed to store users' LBTC, which will be used by the network to issue and burn Tick and Verifier UTXOs.

## 5.2. Compilation parameters

1. STORM\_EYE\_ASSET\_ID \- the Storm Eye asset ID that will be used for the network authorization.  
2. ACCOUNT\_OWNER\_PUBKEY \- the account owner Schnorr pubkey

## 5.3. Spending paths

The Verifier asset contract has next spending paths:

1. Network authorized spending

### 5.3.1. Network authorized spending

In this scenario, the network can spend a user Account UTXO. To spend it, the network must include the Storm Eye UTXO in the transaction.

The following witness parameters are accepted for spending:

1. *storm\_eye\_input\_index* \- the Storm Eye UTXO input index  

This spending path will include the following checks:

1. assert(jet::input\_asset(*storm\_eye\_input\_index*) \== param::STORM\_EYE\_ASSET\_ID)  

# 6\. Treasury contract

## 6.1. Description

This contract is intended to store the Oracle network's LBTC asset, which can be used to pay fees for system transactions.

## 6.2. Compilation parameters

1. STORM\_EYE\_ASSET\_ID \- the Storm Eye asset ID that will be used for the network authorization.

## 6.3. Spending paths

The Verifier asset contract has next spending paths:

1. Network authorized spending

### 6.3.1. Network authorized spending

In this scenario, the network can spend a user Treasury UTXO. To spend it, the network must include the Storm Eye UTXO in the transaction.

The following witness parameters are accepted for spending:

1. *storm\_eye\_input\_index* \- the Storm Eye UTXO input index  

This spending path will include the following checks:

1. assert(jet::input\_asset(*storm\_eye\_input\_index*) \== param::STORM\_EYE\_ASSET\_ID)  
