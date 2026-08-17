# Solana-Like-BlockChain
================================================================================
 solana_like_chain.py -- A Solana-inspired blockchain, simplified & educational
================================================================================

A single-file simulation of a Solana-style blockchain. It's meant to teach
the core ideas behind Solana's design, not to be a production system.

Solana concepts modeled here:
  1. Proof of History (PoH)   - a verifiable sequential hash chain that acts
                                 as a decentralized, trustless clock. This is
                                 Solana's signature idea: instead of nodes
                                 talking to each other to agree on "when"
                                 something happened, everyone can
                                 independently recompute the hash chain and
                                 verify order/time.
  2. Accounts model            - like Solana (and unlike Bitcoin's UTXO
                                 model), state is just a table of accounts
                                 with balances, addressed by public key.
  3. Ed25519 signatures        - the actual signature scheme Solana uses.
  4. Stake-weighted leadership - validators get a turn to produce blocks
                                 ("slots") in proportion to how much stake
                                 they hold, deterministically computed ahead
                                 of time (a simplified "leader schedule").
  5. Lamports & fees           - balances are tracked in lamports (1 SOL =
                                 1,000,000,000 lamports); every transaction
                                 pays a small fee to that slot's leader.
  6. Recent-blockhash replay
     protection                - instead of per-account nonces (like
                                 Ethereum), transactions reference a recent
                                 block hash and expire once that hash rolls
                                 out of the recent-history window.

What's deliberately left out (real Solana is a multi-year, multi-million-line
distributed system):
  - Networking / gossip (Turbine, Gulf Stream) -- everything here runs in one
    process, one thread.
  - Tower BFT voting / fork choice -- we just keep a single linear chain.
  - Sealevel's parallel runtime and on-chain programs (BPF) -- no smart
    contracts, just SOL transfers.
  - Real epochs, rent, vote accounts.

Dependency:
    ‘‘‘pip install cryptography’’’

Run it:
    ‘‘‘python solana_like_chain.py’’’
