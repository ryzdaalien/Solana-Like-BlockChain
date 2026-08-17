import hashlib
import random
import sys
import time
from collections import deque
from dataclasses import dataclass, field
from typing import List, Optional

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives import serialization
    from cryptography.exceptions import InvalidSignature
except ImportError:
    sys.exit(
        "This script needs the 'cryptography' package.\n"
        "Install it with:  pip install cryptography"
    )


# ---------------------------------------------------------------------------
# Constants (named the way Solana names them)
# ---------------------------------------------------------------------------
LAMPORTS_PER_SOL = 1_000_000_000
TRANSACTION_FEE_LAMPORTS = 5_000     # flat fee per tx, paid to that slot's leader
TICKS_PER_SLOT = 10                  # tiny vs. real Solana's 64 ticks/slot (each
                                      # tick itself thousands of hashes) -- shrunk
                                      # here so the demo runs instantly
MAX_RECENT_BLOCKHASHES = 5           # how many past block hashes stay valid for new txs


def short(hex_str: str, n: int = 6) -> str:
    """Truncate a hex pubkey/hash for friendlier printing, block-explorer style."""
    return f"{hex_str[:n]}..{hex_str[-4:]}"


# ---------------------------------------------------------------------------
# Wallets / Keypairs  (Ed25519 -- the actual curve Solana uses)
# ---------------------------------------------------------------------------
class Keypair:
    """A wallet: an Ed25519 keypair that can sign transactions."""

    def __init__(self):
        self._private_key = Ed25519PrivateKey.generate()
        self._public_key = self._private_key.public_key()

    @property
    def public_key_bytes(self) -> bytes:
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    @property
    def public_key_hex(self) -> str:
        return self.public_key_bytes.hex()

    def sign(self, message: bytes) -> bytes:
        return self._private_key.sign(message)

    @staticmethod
    def verify(public_key_hex: str, message: bytes, signature_hex: str) -> bool:
        try:
            pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
            pub.verify(bytes.fromhex(signature_hex), message)
            return True
        except (InvalidSignature, ValueError):
            return False


# ---------------------------------------------------------------------------
# Transactions
# ---------------------------------------------------------------------------
class Transaction:
    """
    A signed instruction to move lamports from one account to another.
    Mirrors Solana's real design in two ways:
      - accounts (pubkeys), not UTXOs
      - a recent_blockhash instead of a per-account nonce, for replay
        protection: the tx is only valid while that blockhash is "recent".
    """

    def __init__(self, sender_hex, recipient_hex, lamports, recent_blockhash, memo=""):
        self.sender = sender_hex
        self.recipient = recipient_hex
        self.lamports = lamports
        self.recent_blockhash = recent_blockhash
        self.memo = memo
        self.timestamp = time.time()
        self.signature: Optional[str] = None

    def message(self) -> bytes:
        """The exact bytes that get signed -- change anything here and the signature breaks."""
        payload = f"{self.sender}|{self.recipient}|{self.lamports}|{self.recent_blockhash}|{self.memo}"
        return payload.encode()

    def sign(self, keypair: Keypair):
        if keypair.public_key_hex != self.sender:
            raise ValueError("only the sender's own keypair can sign this transaction")
        self.signature = keypair.sign(self.message()).hex()

    def verify(self) -> bool:
        if not self.signature:
            return False
        return Keypair.verify(self.sender, self.message(), self.signature)

    def __repr__(self):
        sol = self.lamports / LAMPORTS_PER_SOL
        return f"Tx({short(self.sender)} -> {short(self.recipient)}, {sol:.4f} SOL)"


# ---------------------------------------------------------------------------
# Proof of History
# ---------------------------------------------------------------------------
@dataclass
class PoHEntry:
    """
    One entry in the PoH sequence: 'num_hashes' plain hashes happened, and
    then (optionally) a batch of transactions got hashed into the chain,
    cryptographically proving they existed at that point in the sequence.
    """
    num_hashes: int
    hash: str
    tx_signatures: List[str] = field(default_factory=list)


class ProofOfHistory:
    """
    Solana's signature idea. A single thread continuously computes
    hash = SHA256(hash), producing a long chain of hashes. Because SHA-256
    can't be computed faster than sequentially, the *number* of hashes
    between two points is proof that real time passed between them -- a
    "verifiable delay function" doubling as a clock nobody has to trust.

    When data (like a batch of transactions) needs to be timestamped, it
    gets mixed into the next hash: hash = SHA256(hash + data). That data is
    now provably "at" that position in history -- anyone can recompute the
    chain and confirm it landed exactly there.
    """

    def __init__(self, seed: bytes = b"genesis-poh-seed"):
        self.hash = hashlib.sha256(seed).digest()
        self.tick_count = 0
        self._pending_hashes = 0
        self.entries: List[PoHEntry] = []

    def tick(self):
        """Advance the clock by one hash, with no data mixed in."""
        self.hash = hashlib.sha256(self.hash).digest()
        self.tick_count += 1
        self._pending_hashes += 1

    def record(self, transactions: List[Transaction]) -> PoHEntry:
        """Mix a batch of transactions into the chain and emit an entry."""
        data = b"".join(bytes.fromhex(tx.signature) for tx in transactions)
        self.hash = hashlib.sha256(self.hash + data).digest()
        self.tick_count += 1
        self._pending_hashes += 1
        entry = PoHEntry(self._pending_hashes, self.hash.hex(), [tx.signature for tx in transactions])
        self.entries.append(entry)
        self._pending_hashes = 0
        return entry

    def tick_entry(self) -> PoHEntry:
        """Close out an entry made of pure ticks (no transactions arrived this slot)."""
        entry = PoHEntry(self._pending_hashes, self.hash.hex(), [])
        self.entries.append(entry)
        self._pending_hashes = 0
        return entry

    @property
    def hash_hex(self) -> str:
        return self.hash.hex()


def verify_poh_entries(start_hash_hex: str, entries: List[PoHEntry]) -> bool:
    """
    Independently recompute a PoH sequence and check it matches. This is what
    lets any validator (or outside observer) verify 'this data really did
    exist at this point in history' without trusting anyone -- just redo the
    hashing yourself.
    """
    current = bytes.fromhex(start_hash_hex)
    for entry in entries:
        if entry.tx_signatures:
            for _ in range(entry.num_hashes - 1):
                current = hashlib.sha256(current).digest()
            data = b"".join(bytes.fromhex(sig) for sig in entry.tx_signatures)
            current = hashlib.sha256(current + data).digest()
        else:
            for _ in range(entry.num_hashes):
                current = hashlib.sha256(current).digest()
        if current.hex() != entry.hash:
            return False
    return True


# ---------------------------------------------------------------------------
# Blocks
# ---------------------------------------------------------------------------
class Block:
    def __init__(self, slot, previous_hash, leader, transactions, poh_entries, poh_end_hash):
        self.slot = slot
        self.previous_hash = previous_hash
        self.leader = leader
        self.transactions = transactions
        self.poh_entries = poh_entries
        self.poh_end_hash = poh_end_hash
        self.timestamp = time.time()
        self.block_hash = self.compute_hash()
        self.signature: Optional[str] = None

    def compute_hash(self) -> str:
        tx_part = "".join(tx.signature or "" for tx in self.transactions)
        payload = f"{self.slot}|{self.previous_hash}|{self.leader}|{tx_part}|{self.poh_end_hash}"
        return hashlib.sha256(payload.encode()).hexdigest()

    def sign(self, keypair: Keypair):
        self.signature = keypair.sign(bytes.fromhex(self.block_hash)).hex()


# ---------------------------------------------------------------------------
# Validators / stake-weighted leader schedule
# ---------------------------------------------------------------------------
class Validator:
    def __init__(self, name: str, stake_sol: float):
        self.name = name
        self.keypair = Keypair()
        self.stake_lamports = int(stake_sol * LAMPORTS_PER_SOL)

    @property
    def pubkey(self) -> str:
        return self.keypair.public_key_hex


def generate_leader_schedule(validators: List[Validator], num_slots: int, epoch_seed: str) -> List[str]:
    """
    Stake-weighted, deterministic leader selection: whoever holds more stake
    gets picked for proportionally more slots. Deterministic given the same
    seed + stake distribution, so every node can compute the identical
    schedule independently ahead of time (real Solana recalculates this once
    per epoch, ~2-3 days on mainnet).
    """
    rng = random.Random(epoch_seed)
    total_stake = sum(v.stake_lamports for v in validators)
    schedule = []
    for _ in range(num_slots):
        pick = rng.uniform(0, total_stake)
        upto = 0
        for v in validators:
            upto += v.stake_lamports
            if upto >= pick:
                schedule.append(v.pubkey)
                break
    return schedule


# ---------------------------------------------------------------------------
# The cluster itself -- ties PoH, accounts, leader schedule, and blocks together
# ---------------------------------------------------------------------------
class SolanaCluster:
    def __init__(self, validators: List[Validator], epoch_slots: int = 500):
        if not validators:
            raise ValueError("need at least one validator")
        self.validators = {v.pubkey: v for v in validators}
        self.validator_list = validators
        self.poh = ProofOfHistory()
        self.slot = 0
        self.blocks: List[Block] = []
        self.accounts: dict = {}                 # pubkey_hex -> lamports
        self.recent_blockhashes = deque(maxlen=MAX_RECENT_BLOCKHASHES)
        self.processed_signatures = set()
        self.pending_transactions: List[Transaction] = []
        self.leader_schedule = generate_leader_schedule(validators, epoch_slots, epoch_seed="epoch-0")
        self._create_genesis_block()

    def _create_genesis_block(self):
        genesis = Block(0, "0" * 64, "genesis", [], [], self.poh.hash_hex)
        self.blocks.append(genesis)
        self.recent_blockhashes.append(genesis.block_hash)

    # -- balances -------------------------------------------------------
    def airdrop(self, pubkey_hex: str, sol_amount: float):
        """Devnet-style faucet: mint lamports out of thin air. Out-of-band,
        like Solana's airdrop RPC call -- not a normal peer-to-peer transfer."""
        lamports = int(sol_amount * LAMPORTS_PER_SOL)
        self.accounts[pubkey_hex] = self.accounts.get(pubkey_hex, 0) + lamports

    def get_balance(self, pubkey_hex: str) -> float:
        return self.accounts.get(pubkey_hex, 0) / LAMPORTS_PER_SOL

    # -- transactions -----------------------------------------------------
    def build_transaction(self, sender: Keypair, recipient_hex: str, sol_amount: float, memo: str = "") -> Transaction:
        lamports = int(sol_amount * LAMPORTS_PER_SOL)
        recent_blockhash = self.blocks[-1].block_hash
        tx = Transaction(sender.public_key_hex, recipient_hex, lamports, recent_blockhash, memo)
        tx.sign(sender)
        return tx

    def submit_transaction(self, tx: Transaction):
        if not tx.verify():
            raise ValueError("invalid signature")
        if tx.recent_blockhash not in self.recent_blockhashes:
            raise ValueError("blockhash not recent (expired)")
        if tx.signature in self.processed_signatures or any(p.signature == tx.signature for p in self.pending_transactions):
            raise ValueError("duplicate transaction (replay)")
        self.pending_transactions.append(tx)

    # -- block production -------------------------------------------------
    def produce_block(self) -> Block:
        next_slot = self.slot + 1
        leader_pubkey = self.leader_schedule[next_slot % len(self.leader_schedule)]
        leader = self.validators[leader_pubkey]

        # transactions whose recent_blockhash rolled out of the window are
        # no longer valid and get dropped, just like on real Solana
        live = [tx for tx in self.pending_transactions if tx.recent_blockhash in self.recent_blockhashes]

        applied, skipped = [], []
        for tx in live:
            if self._apply_transaction(tx, leader_pubkey):
                applied.append(tx)
                self.processed_signatures.add(tx.signature)
            else:
                skipped.append(tx)

        for _ in range(TICKS_PER_SLOT):
            self.poh.tick()
        entry = self.poh.record(applied) if applied else self.poh.tick_entry()

        self.slot = next_slot
        block = Block(self.slot, self.blocks[-1].block_hash, leader_pubkey, applied, [entry], self.poh.hash_hex)
        block.sign(leader.keypair)

        self.blocks.append(block)
        self.recent_blockhashes.append(block.block_hash)
        self.pending_transactions = skipped
        return block

    def _apply_transaction(self, tx: Transaction, fee_recipient: str) -> bool:
        total_cost = tx.lamports + TRANSACTION_FEE_LAMPORTS
        if self.accounts.get(tx.sender, 0) < total_cost:
            return False
        self.accounts[tx.sender] -= total_cost
        self.accounts[tx.recipient] = self.accounts.get(tx.recipient, 0) + tx.lamports
        self.accounts[fee_recipient] = self.accounts.get(fee_recipient, 0) + TRANSACTION_FEE_LAMPORTS
        return True

    # -- verification -----------------------------------------------------
    def verify_chain(self):
        """Recompute everything from scratch: hash links, PoH sequences,
        leader signatures, and every transaction signature."""
        for i in range(1, len(self.blocks)):
            block, prev = self.blocks[i], self.blocks[i - 1]
            if block.previous_hash != prev.block_hash:
                return False, f"slot {block.slot}: previous_hash doesn't match the prior block"
            if block.compute_hash() != block.block_hash:
                return False, f"slot {block.slot}: block hash doesn't match its contents (tampered?)"
            if not Keypair.verify(block.leader, bytes.fromhex(block.block_hash), block.signature):
                return False, f"slot {block.slot}: leader signature invalid"
            if not verify_poh_entries(prev.poh_end_hash, block.poh_entries):
                return False, f"slot {block.slot}: Proof of History sequence invalid"
            for tx in block.transactions:
                if not tx.verify():
                    return False, f"slot {block.slot}: transaction {short(tx.signature)} has an invalid signature"
        return True, "chain verified OK -- all hashes, PoH sequences, and signatures check out"


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------
def main():
    print("=" * 78)
    print(" SOLANA-LIKE BLOCKCHAIN -- single-file educational simulation")
    print("=" * 78)
    print(" Modeling: Proof of History, Ed25519-signed transactions, an accounts")
    print(" ledger (lamports), stake-weighted leader rotation, and per-tx fees.\n")

    # ---- 1. Validators & stake --------------------------------------------
    print("[1] Spinning up validators -- stake determines how often each one leads")
    validators = [
        Validator("Validator-Nova", stake_sol=50),
        Validator("Validator-Comet", stake_sol=30),
        Validator("Validator-Pulsar", stake_sol=20),
    ]
    for v in validators:
        print(f"    {v.name:<18} stake={v.stake_lamports / LAMPORTS_PER_SOL:>5.1f} SOL   pubkey={short(v.pubkey)}")

    cluster = SolanaCluster(validators, epoch_slots=200)

    tally = {}
    for pk in cluster.leader_schedule:
        tally[pk] = tally.get(pk, 0) + 1
    n = len(cluster.leader_schedule)
    total_stake = sum(v.stake_lamports for v in validators)
    print(f"\n    Leader schedule computed for the epoch ({n} slots) -- sampled result:")
    for v in validators:
        got = tally.get(v.pubkey, 0)
        print(f"      {v.name:<18} leads {got:>3} slots  (~{100*got/n:.0f}% of slots vs "
              f"{100*v.stake_lamports/total_stake:.0f}% of stake)")

    # ---- 2. Wallets & airdrop ----------------------------------------------
    print("\n[2] Creating user wallets and airdropping devnet SOL")
    dara, eli = Keypair(), Keypair()
    cluster.airdrop(dara.public_key_hex, 10)
    cluster.airdrop(eli.public_key_hex, 10)
    print(f"    Dara  {short(dara.public_key_hex)}   balance = {cluster.get_balance(dara.public_key_hex):.2f} SOL")
    print(f"    Eli   {short(eli.public_key_hex)}   balance = {cluster.get_balance(eli.public_key_hex):.2f} SOL")

    # ---- 3. Transactions that should be rejected ---------------------------
    print("\n[3] A couple of transactions that SHOULD be rejected")
    forged = cluster.build_transaction(dara, eli.public_key_hex, 1.0)
    forged.lamports = 999_000_000_000  # tampered after signing
    try:
        cluster.submit_transaction(forged)
    except ValueError as e:
        print(f"    tampered post-signature amount -> rejected ({e})")

    dup = cluster.build_transaction(dara, eli.public_key_hex, 0.5)
    cluster.submit_transaction(dup)
    try:
        cluster.submit_transaction(dup)
    except ValueError as e:
        print(f"    resubmitting the same tx        -> rejected ({e})")

    # ---- 4. Real transfers + block production ------------------------------
    print("\n[4] Submitting transfers and producing blocks (slots)")
    print("    (round 3 has Eli try to send 50 SOL he doesn't have -- watch it get")
    print("     submitted fine but skipped every time a block is produced)")
    validator_names = {v.pubkey: v.name for v in validators}
    rounds = [
        [(dara, eli, 1.2), (eli, dara, 0.4)],
        [(dara, eli, 0.3)],
        [(eli, dara, 50.0), (dara, eli, 0.2)],
        [(eli, dara, 1.0)],
        [(dara, eli, 0.15), (eli, dara, 0.05)],
    ]
    for round_num, round_txs in enumerate(rounds, start=1):
        for sender, recipient, amount in round_txs:
            tx = cluster.build_transaction(sender, recipient.public_key_hex, amount)
            try:
                cluster.submit_transaction(tx)
            except ValueError as e:
                print(f"    round {round_num}: submit rejected ({e})")
        block = cluster.produce_block()
        leader_name = validator_names[block.leader]
        print(f"    slot {block.slot:>2}  leader={leader_name:<18} applied={len(block.transactions)}  "
              f"pending_after={len(cluster.pending_transactions)}  "
              f"poh_hashes_total={cluster.poh.tick_count:<4}  block_hash={short(block.block_hash)}")

    # ---- 5. Final balances --------------------------------------------------
    print("\n[5] Final balances")
    print(f"    Dara               {cluster.get_balance(dara.public_key_hex):.6f} SOL")
    print(f"    Eli                {cluster.get_balance(eli.public_key_hex):.6f} SOL")
    for v in validators:
        print(f"    {v.name:<18} {cluster.get_balance(v.pubkey):.6f} SOL  (earned from tx fees as leader)")

    # ---- 6. Proof of History, verified independently -----------------------
    print("\n[6] Verifying Proof of History for slot 1, independently")
    genesis, slot1 = cluster.blocks[0], cluster.blocks[1]
    hashes_done = sum(e.num_hashes for e in slot1.poh_entries)
    ok = verify_poh_entries(genesis.poh_end_hash, slot1.poh_entries)
    print(f"    Recomputed {hashes_done} chained SHA-256 hashes starting from genesis's end-hash...")
    print(f"    Result matches the hash the leader published: {ok}")

    # ---- 7. Full chain verification -----------------------------------------
    print("\n[7] Verifying the whole chain (hash links, PoH, every signature)")
    ok, msg = cluster.verify_chain()
    print(f"    {msg}")

    # ---- 8. Tamper demo -------------------------------------------------
    print("\n[8] What happens if someone edits the ledger after the fact?")
    victim_block = next(b for b in cluster.blocks if b.transactions)
    victim_tx = victim_block.transactions[0]
    original_amount = victim_tx.lamports
    print(f"    Rewriting slot {victim_block.slot}'s first tx: "
          f"{original_amount/LAMPORTS_PER_SOL:.4f} SOL -> "
          f"{(original_amount + 100*LAMPORTS_PER_SOL)/LAMPORTS_PER_SOL:.4f} SOL")
    victim_tx.lamports += 100 * LAMPORTS_PER_SOL
    ok, msg = cluster.verify_chain()
    print(f"    Chain verification now says: {msg}")
    print("    (deleting a transaction from a block instead of editing one would be")
    print("     caught by the block-hash check rather than the signature check)")

    victim_tx.lamports = original_amount
    ok, msg = cluster.verify_chain()
    print(f"    Restored the original value -- verification: {msg}")

    print("\n" + "=" * 78)
    print(f" Done. {cluster.slot} slots produced, {len(cluster.blocks)} blocks total, "
          f"{cluster.poh.tick_count} total PoH hashes computed.")
    print("=" * 78)


if __name__ == "__main__":
    main()
