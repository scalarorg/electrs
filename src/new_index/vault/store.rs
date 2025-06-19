use super::{TxVaultInfo, TxVaultKey, TxVaultRow};
use crate::new_index::{DBRow, DB};
use std::path::Path;

use crate::config::Config;
use crate::errors::*;
use crate::new_index::DBFlush;

const HASH_LEN: usize = 32;

pub enum DBType {
    Tx,
    MerklePath,
    MerkleTree,
}

pub struct VaultStore {
    vault_txs: DB,
    vault_merkle_path: DB,
    vault_merkle_tree: DB,
}

impl VaultStore {
    pub fn open(path: &Path, config: &Config) -> Self {
        let vault_txs = DB::open(&path.join("vaulttxs"), config);
        let vault_merkle_path = DB::open(&path.join("vaultmerklepath"), config);
        let vault_merkle_tree = DB::open(&path.join("vaultmerkletree"), config);
        Self {
            vault_txs,
            vault_merkle_path,
            vault_merkle_tree,
        }
    }
    pub fn vault_txs(&self) -> &DB {
        &self.vault_txs
    }
    pub fn vault_merkle_tree(&self) -> &DB {
        &self.vault_merkle_path
    }
    
    pub fn flush(&self, db_type: DBType, vault_rows: Vec<DBRow>) {
        match db_type {
            DBType::Tx => self.vault_txs.write(vault_rows, DBFlush::Enable),
            DBType::MerklePath => self.vault_merkle_path.write(vault_rows, DBFlush::Enable),
            DBType::MerkleTree => self.vault_merkle_tree.write(vault_rows, DBFlush::Enable),
        }
    }

    pub fn get_vault_info(&self, key: &TxVaultKey) -> Result<TxVaultInfo> {
        let key = key.as_bytes();
        let value = self
            .vault_txs
            .get(key.as_slice())
            .chain_err(|| "TxVault not found")?;
        TxVaultInfo::try_from_bytes(value.as_slice()).chain_err(|| "Invalid value")
    }
    pub fn get_transactions_from_hash(
        &self,
        batch_size: usize,
        last_vault_tx_hash: Option<&str>,
    ) -> Result<Vec<TxVaultRow>> {
        let last_key = last_vault_tx_hash
            .map(|v| TxVaultKey::try_from_hex(v))
            .transpose()?;
        let mut tx_vaults = Vec::new();
        let mut iter = match last_key {
            Some(key) => {
                debug!("Get latest vault tx from key: {:?}", &key);
                // let mut iter = self
                //     .vault_txs()
                //     .forward_iterator_from(key.as_bytes().as_slice());
                let mut iter = self.vault_txs().raw_iterator();
                iter.seek(key.as_bytes());
                iter.next();
                iter
            }

            None => {
                let mut iter = self.vault_txs().raw_iterator();
                iter.seek_to_first();
                iter
            }
        };
        while (tx_vaults.len() < batch_size) && iter.valid() {
            if let (Some(key), Some(value)) = (iter.key(), iter.value()) {
                debug!("key: {:?} with length {:?}", hex::encode(key), key.len());
                if key.len() >= HASH_LEN + 8 {
                    let row = TxVaultRow::try_from_bytes(&key[0..], &value)?;
                    debug!("TxVaultRow: {:?}", row);
                    tx_vaults.push(row);
                }
            }
            iter.next();
        }
        Ok(tx_vaults)
    }
    pub fn get_last_vault(&self) -> Result<TxVaultRow> {
        let mut iter = self.vault_txs().raw_iterator();
        iter.seek_to_last();
        while iter.valid() {
            let Some(row) = iter
                .key()
                .zip(iter.value())
                .and_then(|(key, value)| TxVaultRow::try_from_bytes(&key[0..], &value).ok())
            else {
                debug!("No vault transaction found. Try to get previous item");
                iter.prev();
                continue;
            };
            debug!("Get last vault transaction: {:?}", row);
            return Ok(row);
        }
        Err(Error::from("No vault transaction found"))
    }
}
