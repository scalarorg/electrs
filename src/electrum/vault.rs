use std::sync::Arc;

use crate::errors::Result;
use crate::new_index::vault::{TxVaultInfo, TxVaultRow};
use crate::new_index::Query;

pub struct VaultServer {
    query: Arc<Query>,
}

impl VaultServer {
    pub fn new(query: Arc<Query>) -> Self {
        Self { query }
    }
    pub fn get_transactions_from_hash(
        &self,
        hash: Option<Vec<u8>>,
        length: usize,
    ) -> Result<Vec<TxVaultInfo>> {
        let vault_store = self.query.chain().store().vault_store();
        let tx_vaults = vault_store.get_transactions_from_hash(hash, length)?;
        Ok(tx_vaults)
    }
    pub fn get_lastest_transactions(
        &self,
        batch_size: usize,
        // Hex String param form client
        last_vault_tx_hash: Option<&str>,
    ) -> Result<Vec<TxVaultRow>> {
        let vault_store = self.query.chain().store().vault_store();
        vault_store.get_lastest_transactions(batch_size, last_vault_tx_hash)
    }
}
