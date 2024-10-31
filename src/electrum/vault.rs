use std::sync::Arc;

use crate::errors::Result;
use crate::new_index::vault::{TxVaultInfo, TxVaultKey};
use crate::new_index::Query;
use bitcoin::hashes::sha256d::Hash as Sha256dHash;
use bitcoin::hashes::Hash;

pub struct VaultServer {
    query: Arc<Query>,
}

impl VaultServer {
    pub fn new(query: Arc<Query>) -> Self {
        Self { query }
    }
    pub fn get_transactions(&self, hash: &Sha256dHash, length: usize) -> Result<Vec<TxVaultInfo>> {
        let _key = TxVaultKey::new(hash.to_byte_array());
        let vault_store = self.query.chain().store().vault_store();
        let tx_vaults = vault_store.get_transactions_from_hash(hash.as_byte_array(), length)?;
        Ok(tx_vaults)
    }
    pub fn get_lastest_transaction(&self) -> Result<TxVaultInfo> {
        let vault_store = self.query.chain().store().vault_store();
        vault_store.get_lastest_transaction()
    }
}
