mod codec;
pub mod header;
mod layout;

use bitcoin::{consensus::Encodable, hashes::Hash, Transaction};
use keccak_hasher::KeccakHasher;
use layout::KeccakTrieLayout;
use memory_db::{HashKey, MemoryDB};
use trie_db::{TrieDBMutBuilder, TrieMut};

/// Constants used into trie simplification codec.
mod trie_constants {
    const FIRST_PREFIX: u8 = 0b_00 << 6;
    pub const LEAF_PREFIX_MASK: u8 = 0b_01 << 6;
    pub const BRANCH_WITHOUT_MASK: u8 = 0b_10 << 6;
    pub const BRANCH_WITH_MASK: u8 = 0b_11 << 6;
    pub const EMPTY_TRIE: u8 = FIRST_PREFIX | (0b_00 << 4);
    pub const ALT_HASHING_LEAF_PREFIX_MASK: u8 = FIRST_PREFIX | (0b_1 << 5);
    pub const ALT_HASHING_BRANCH_WITH_MASK: u8 = FIRST_PREFIX | (0b_01 << 4);
    pub const ESCAPE_COMPACT_HEADER: u8 = EMPTY_TRIE | 0b_00_01;
}

pub fn build_trie_db(block_entry: &crate::new_index::BlockEntry, rows: &[&Transaction]) {
    let mut db = MemoryDB::<KeccakHasher, HashKey<KeccakHasher>, Vec<u8>>::default();
    let mut root = Default::default();
    let mut trie = TrieDBMutBuilder::<KeccakTrieLayout>::new(&mut db, &mut root).build();
    for tx in rows.iter() {
        let height = block_entry.entry.height() as u32;
        let txid = tx.compute_txid();
        let key = txid.as_raw_hash().as_byte_array();
        let mut writer = vec![];
        if let Ok(_) = tx.consensus_encode(&mut writer) {
            let _ = trie.insert(key.as_slice(), writer.as_slice());
        }
    }
}
