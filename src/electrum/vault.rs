use std::sync::Arc;

use crate::errors::Result;
use crate::new_index::vault::TxVaultRow;
use crate::new_index::Query;

pub struct VaultServer {
    query: Arc<Query>,
}

impl VaultServer {
    pub fn new(query: Arc<Query>) -> Self {
        Self { query }
    }
    pub fn get_last_vault(&self) -> Result<TxVaultRow> {
        let vault_store = self.query.chain().store().vault_store();
        let res = vault_store.get_last_vault();
        if res.is_err() {
            warn!("get_last_vault error: {:?}", res);
        }
        res
    }
    /// Get the latest transactions from the vault
    ///
    /// # Arguments
    ///
    /// * `batch_size` - The number of transactions to return
    /// * `last_vault_tx_hash` - The hash of the last transaction to return
    /// # Returns
    /// A vector of `TxVaultRow` with the latest transactions, don't include the last_vault_tx_hash
    pub fn get_transactions_from_hash(
        &self,
        batch_size: usize,
        // Hex String param form client
        last_vault_tx_hash: Option<&str>,
    ) -> Result<Vec<TxVaultRow>> {
        let vault_store = self.query.chain().store().vault_store();
        vault_store.get_transactions_from_hash(batch_size, last_vault_tx_hash)
    }
}
