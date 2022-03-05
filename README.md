# Safer custody with CTV vaults

**Abstract:** This demonstrates an implementation of simple, "single-hop" vaults
using the proposed `OP_CHECKTEMPLATEVERIFY` opcode. 

OP_CTV allows the vault strategy
to be used without the need to maintain critical presigned transaction data for the lifetime of the vault, as in
the case of previous vault implementations. This
approach is much simpler operationally, since all relevant data aside from key
material can be regenerated algorithmically. This makes vaulting, which increases
custodial safety significantly, more practical at any scale.

The code included here is intended to be approachable and easy to read, though
it would probably need review and tweaking before real-world use. It should be
considered a toy in its current form.

### Vault basics

*Vaulting* is a technique for putting constraints around how bitcoins can be spent.
The constraints are designed in such a way to limit the threat of failure 
(due to key loss or attempted confiscation) during the custody process. Vaults provide
safety improvements that are significant to both individuals performing self-custody
and institutions securing large amounts of bitcoin on behalf of their customers.

The basic idea of a vault is that you predetermine the path the coins in the vault
are allowed to travel, which lets you design the flow of funds so that you have
a chance to intervene in a known way if something unexpected
happens.

For example, in the basic "single-hop" vault structure implemented here, once a 
user vaults their coins, they can either unvault the balance to a key designated
as the "cold" wallet immediately, or they can begin the unvault process and, after a
block delay configurable by the user, spend the coins to a key designated as the
"hot" wallet.

```mermaid
flowchart TD
  A(UTXO you want to vault) --> V(Coin in vault)
  V --> U("Begin the unvaulting process<br/>&lpar;broadcast unvault tx&rpar;")
  U --> C("To the cold wallet<br/>&lpar;immediately&rpar;")
  U --> D("To the hot wallet<br/>&lpar;after an n block delay&rpar;")
```

This allows the user to intervene if they see that an unvault process
has been started unexpectedly: if an attacker Mallory gains control of the user Alice's hot wallet and wants to 
steal the vaulted coins, Mallory has to broadcast the unvault transaction. If Alice
is watching the mempool/chain, she will see that the unvault transaction has been
unexpectedly broadcast, and she can immediately sweep the balance to her cold wallet,
while Mallory must wait the block delay to succeed in stealing funds.

### Vault complexity 

Vaults can either be *limited* or *recursive*. In a recursive vault, the vault can
feed back into itself, potentially allowing the coins to remain in the vault after
an arbitrary number of steps or partial unvaultings.

The vault pattern implemented here is "limited" - it entails a single decision point, and atomically 
unvaults the entire value. Despite being limited, this still provides high utility 
for users. In fact, its simplicity may make it preferable to more complicated schemes.


```mermaid
flowchart TD
  A(UTXO you want to vault) -->|"[some spend] e.g. P2WPKH"| V(to_vault_tx<br/>Coins are now vaulted)
  V -->|"<code>&lt;H(unvault_tx)&gt; OP_CHECKTEMPLATEVERIFY</code>"| U(unvault_tx<br/>Begin the unvaulting process)
  U -->|"<code>&lt;H(to_cold_tx)&gt; OP_CHECKTEMPLATEVERIFY</code>"| C(to_cold_tx)
  U -->|"<code>&lt;block_delay&gt; OP_CSV<br />&lt;hot_pubkey&gt; OP_CHECKSIG</code>"| D(<code>to_hot</code> tx)
  C -->|"<code>&lt;cold_pubkey&gt; OP_CHECKSIG</code>"| E(some undefined destination)
```

For now: `pip install -r requirements.txt && ./main.py`.

## Prior work
- Vaults by kanzure: https://github.com/kanzure/python-vaults

- What do I need to keep track of?
  - just the algorithm
  - vs. presigned txns, which are bearer assets - data needs to be stored for
    perpetuity

- How do fees work?
