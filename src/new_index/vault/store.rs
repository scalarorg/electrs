use bitcoin::hashes::Hash;
use bitcoin::BlockHash;

use super::db::DBFlush;
use super::{DBRow, DB};
use super::{TxVaultInfo, TxVaultKey, TxVaultRow};
use std::path::Path;

use crate::config::Config;
use crate::errors::*;
use crate::new_index::vault::BlockVaultRow;

const HASH_LEN: usize = 32;

pub struct VaultStore {
    //vault_txs: DB, //Store map TxVaultKey to TxVaultInfo
    // vault_headers: DB, //Store map BlockHeight to list of tx positions if has any
    vault_blocks: DB, //Store map BlockHeight to list of TxVaultRow
}

impl VaultStore {
    pub fn open(path: &Path, config: &Config) -> Self {
        //let vault_txs = DB::open(&path.join("vaulttxs"), config);
        let vault_blocks = DB::open(&path.join("vaultblocks"), config);
        Self { vault_blocks }
    }
    // pub fn vault_txs(&self) -> &DB {
    //     &self.vault_txs
    // }
    pub fn vault_blocks(&self) -> &DB {
        &self.vault_blocks
    }
}

//Blocks
impl VaultStore {
    pub fn flush_vault_blocks(&self, rows: Vec<DBRow>) {
        self.vault_blocks.write(rows, DBFlush::Enable);
    }
    pub fn get_vault_block_from_hash(
        &self,
        batch_size: usize,
        last_block_hash: Option<BlockHash>,
    ) -> Result<Vec<BlockVaultRow>> {
        debug!(
            "Get vault block with batch size: {:?} from hash: {:?}",
            batch_size, last_block_hash
        );
        let last_key = last_block_hash.and_then(|v| {
            hex::decode(v)
                .map_err(|e| Error::from(e.to_string()))
                .and_then(|e| {
                    BlockHash::from_slice(e.as_slice()).map_err(|e| Error::from(e.to_string()))
                })
                .ok()
        });
        let mut block_vaults = Vec::new();
        let mut iter = match last_key {
            Some(key) => {
                debug!("Get latest vault tx from key: {:?}", &key);
                // let mut iter = self
                //     .vault_txs()
                //     .forward_iterator_from(key.as_bytes().as_slice());
                let mut iter = self.vault_blocks().raw_iterator();
                iter.seek(key.as_byte_array());
                iter.next();
                iter
            }

            None => {
                let mut iter = self.vault_blocks().raw_iterator();
                iter.seek_to_first();
                iter
            }
        };
        while (block_vaults.len() < batch_size) && iter.valid() {
            if let (Some(key), Some(value)) = (iter.key(), iter.value()) {
                debug!("key: {:?} with length {:?}", hex::encode(key), key.len());
                match BlockVaultRow::try_from_bytes(&key, &value) {
                    Ok(row) => block_vaults.push(row),
                    Err(e) => {
                        error!("Failed to deserialize BlockVaultRow: {:?}", e);
                    }
                }
            }
            iter.next();
        }
        Ok(block_vaults)
    }
    pub fn get_last_vault_block(&self) -> Result<BlockVaultRow> {
        let mut iter = self.vault_blocks().raw_iterator();
        iter.seek_to_last();
        while iter.valid() {
            let Some(block) = iter
                .key()
                .zip(iter.value())
                .and_then(|(key, value)| BlockVaultRow::try_from_bytes(&key, &value).ok())
            else {
                debug!("No vault block found. Try to get previous item");
                iter.prev();
                continue;
            };
            debug!("Get last vault block: {:?}", block);
            return Ok(block);
        }
        Err(Error::from("No vault block found"))
    }
}
//Transactions
// impl VaultStore {
//     pub fn flush_vault_tx(&self, vault_rows: Vec<DBRow>) {
//         self.vault_txs.write(vault_rows, DBFlush::Enable);
//     }
//     pub fn get_vault_info(&self, key: &TxVaultKey) -> Result<TxVaultInfo> {
//         let key = key.as_bytes();
//         let value = self
//             .vault_txs
//             .get(key.as_slice())
//             .chain_err(|| "TxVault not found")?;
//         TxVaultInfo::try_from_bytes(value.as_slice()).chain_err(|| "Invalid value")
//     }
//     pub fn get_transactions_from_hash(
//         &self,
//         batch_size: usize,
//         last_vault_tx_hash: Option<&str>,
//     ) -> Result<Vec<TxVaultRow>> {
//         let last_key = last_vault_tx_hash
//             .map(|v| TxVaultKey::try_from_hex(v))
//             .transpose()?;
//         let mut tx_vaults = Vec::new();
//         let mut iter = match last_key {
//             Some(key) => {
//                 debug!("Get latest vault tx from key: {:?}", &key);
//                 // let mut iter = self
//                 //     .vault_txs()
//                 //     .forward_iterator_from(key.as_bytes().as_slice());
//                 let mut iter = self.vault_txs().raw_iterator();
//                 iter.seek(key.as_bytes());
//                 iter.next();
//                 iter
//             }

//             None => {
//                 let mut iter = self.vault_txs().raw_iterator();
//                 iter.seek_to_first();
//                 iter
//             }
//         };
//         while (tx_vaults.len() < batch_size) && iter.valid() {
//             if let (Some(key), Some(value)) = (iter.key(), iter.value()) {
//                 debug!("key: {:?} with length {:?}", hex::encode(key), key.len());
//                 if key.len() >= HASH_LEN + 8 {
//                     let row = TxVaultRow::try_from_bytes(&key[0..], &value)?;
//                     debug!("TxVaultRow: {:?}", row);
//                     tx_vaults.push(row);
//                 }
//             }
//             iter.next();
//         }
//         Ok(tx_vaults)
//     }
//     pub fn get_last_vault(&self) -> Result<TxVaultRow> {
//         let mut iter = self.vault_txs().raw_iterator();
//         iter.seek_to_last();
//         while iter.valid() {
//             let Some(row) = iter
//                 .key()
//                 .zip(iter.value())
//                 .and_then(|(key, value)| TxVaultRow::try_from_bytes(&key[0..], &value).ok())
//             else {
//                 debug!("No vault transaction found. Try to get previous item");
//                 iter.prev();
//                 continue;
//             };
//             debug!("Get last vault transaction: {:?}", row);
//             return Ok(row);
//         }
//         Err(Error::from("No vault transaction found"))
//     }
// }
