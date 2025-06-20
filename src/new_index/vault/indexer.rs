use std::sync::Arc;

use super::schema::lookup_txo;
use super::{BlockEntry, Store, TxVaultInfo, TxVaultKey, TxVaultRow};
use crate::chain::{Network, Transaction};
use crate::new_index::vault::model::BlockVaultRow;
use crate::util::ScriptToAddr;
use bitcoin::hashes::Hash;
use bitcoin::{OutPoint, ScriptBuf, TxIn, TxOut};
use bitcoin_vault::types::error::ParserError;
use bitcoin_vault::{ParsingStaking, StakingParser};
use rayon::prelude::*;

pub struct VaultIndexer {
    network: Network,
    tag: Vec<u8>,
    version: u8,
    staking_parser: StakingParser,
    store: Arc<Store>,
}

impl VaultIndexer {
    pub fn new(network: Network, tag: Vec<u8>, version: u8, store: Arc<Store>) -> Self {
        let staking_parser = StakingParser::new(tag.clone(), version);
        Self {
            network,
            tag,
            version,
            staking_parser,
            store,
        }
    }
    pub fn index_blocks(&self, block_entries: &[BlockEntry]) {
        let block_vaults = block_entries
            .iter()
            .map(|block_entry| {
                let mut block_vault_row = BlockVaultRow::new(
                    block_entry.entry.hash().clone(),
                    block_entry.entry.height(),
                );
                for (idx, tx) in block_entry.block.txdata.iter().enumerate() {
                    let height = block_entry.entry.height();
                    let block_timestamp = block_entry.entry.header().time;
                    if let Ok(vault_row) = self.index_transaction(
                        tx,
                        height as u32,
                        hex::encode(block_entry.entry.hash().as_byte_array()),
                        idx as u32,
                        block_timestamp,
                    ) {
                        block_vault_row.add_tx(vault_row.info);
                    }
                }
                block_vault_row
            })
            .collect::<Vec<BlockVaultRow>>();
        //let mut vault_rows = vec![];
        let mut block_rows = vec![];
        let mut empty_block = vec![]; //We need to remove empty block rows from the db incase of reorg
        for block_vault in block_vaults.into_iter() {
            //vault_rows.extend(vault_txs.into_iter().map(|tx| tx.into_row()));
            if block_vault.tx_infos.len() > 0 {
                info!(
                    "Found vault block at height: {:?} with hash: {:?}, number of txs: {:?}",
                    block_vault.height,
                    block_vault.hash,
                    block_vault.tx_infos.len()
                );
                block_rows.push(block_vault.into_row());
            } else {
                empty_block.push(block_vault.height);
            }
        }
        let vault_store = self.store.vault_store();
        //vault_store.flush_vault_tx(vault_rows);
        vault_store.flush_vault_blocks(block_rows);
        if !empty_block.is_empty() {
            vault_store.remove_empty_vault_blocks(empty_block);
        }
    }
    // pub fn index_blocks(&self, block_entries: &[BlockEntry]) {
    //     let vault_rows: Vec<TxVaultRow> = block_entries
    //         .par_iter() // serialization is CPU-intensive
    //         .map(|b| {
    //             let mut rows = vec![];
    //             for (idx, tx) in b.block.txdata.iter().enumerate() {
    //                 let height = b.entry.height() as u32;
    //                 let block_timestamp = b.entry.header().time;
    //                 if let Ok(vault_row) = self.index_transaction(
    //                     tx,
    //                     height,
    //                     hex::encode(b.entry.hash().as_byte_array()),
    //                     idx as u32,
    //                     block_timestamp,
    //                 ) {
    //                     rows.push(vault_row);
    //                 }
    //             }
    //             //super::merkletree::build_trie_db(b, vault_txes.as_slice());
    //             rows
    //         })
    //         .flatten()
    //         .collect();

    //     if !vault_rows.is_empty() {
    //         //Reorder the rows by height and tx_position
    //         //vault_rows.par_sort_by_key(|row| (row.info.confirmed_height, row.info.tx_position));
    //         let dbrows = vault_rows.into_iter().map(|tx| tx.into_row()).collect();
    //         let vault_store = self.store.vault_store();
    //         vault_store.flush_vault_tx(dbrows);
    //     }
    // }
    fn index_transaction(
        &self,
        tx: &Transaction,
        confirmed_height: u32,
        block_hash: String,
        tx_position: u32,
        block_timestamp: u32,
    ) -> Result<TxVaultRow, ParserError> {
        //Todo: Set staker address and pubkey by first txin
        self.staking_parser.parse(tx).map(|vault_tx| {
            let first_txin = vault_tx.inputs.first();
            let staker_pubkey = self.extract_script_pubkey(first_txin);
            let staker_address = self.extract_staker_address(first_txin);
            //let script_pubkey = first_txin.and_then(|input| input.get_pubkey());
            let mut vault_info = TxVaultInfo::from(vault_tx);
            vault_info.timestamp = block_timestamp;
            vault_info.confirmed_height = confirmed_height;
            vault_info.block_hash = block_hash;
            vault_info.tx_position = tx_position;
            vault_info.staker_pubkey = staker_pubkey;
            vault_info.staker_address = staker_address;
            let vault_key = TxVaultKey::new(
                confirmed_height,
                tx_position,
                vault_info.txid,
                //full_hash(&vault_info.txid[..]),
            );
            let vault_row = TxVaultRow {
                key: vault_key,
                info: vault_info,
            };
            debug!(
                "Parsed block {:?}. Found staking transaction with key {:?}, value {:?}",
                confirmed_height,
                vault_row.key.as_hex(),
                vault_row.info,
            );
            vault_row
        })
    }
    fn extract_staker_address(&self, first_txin: Option<&TxIn>) -> Option<String> {
        let first_txout = first_txin.and_then(|input| self.lookup_txo(&input.previous_output));
        let script_pubkey = first_txout.as_ref().map(|txout| &txout.script_pubkey);
        script_pubkey.and_then(|sb| sb.to_address_str(self.network))
    }
    //Extract script pubkey from first txin
    fn extract_script_pubkey(&self, first_txin: Option<&TxIn>) -> Option<String> {
        let script_pubkey = first_txin
            .and_then(|input| input.witness.iter().nth(1))
            .map(|arr| ScriptBuf::from_bytes(arr.to_vec()));
        script_pubkey.map(|script| script.to_hex_string())
    }
    fn lookup_txo(&self, outpoint: &OutPoint) -> Option<TxOut> {
        lookup_txo(self.store.txstore_db(), outpoint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::consensus::Decodable;
    use bitcoin_vault::types::error::ParserError;
    use std::path::PathBuf;

    use crate::config::Config;

    #[derive(Debug)]
    struct TestData<'a> {
        tx_hex: &'a str,
        amount: u64,
    }

    #[test]
    fn test_vault_indexer_testnet4() {
        let tag = hex::decode("01020304").unwrap();
        let version = 0;
        // let staking_parser = StakingParser::new(tag.clone(), version);
        let config = Config::from_args();
        let path = PathBuf::from("./store");
        let store = Arc::new(Store::open(&path, &config));
        // let vault_txs = DB::open(&path.join("vaulttxs"), &config);
        // let vault_headers = DB::open(&path.join("vaultheader"), &config);
        // let vault_store = Arc::new(VaultStore::new(vault_txs, vault_headers));
        let vault_indexer = VaultIndexer::new(Network::Testnet4, tag, version, store);
        let test_data = TestData {
            tx_hex: "020000000001010c1f10b404affe5fbab0ddb6f859543141fb4be364537c1440ccebffc278c8ba0000000000fdffffff031027000000000000225120f8b6ea762c3caa2faf24ca2b1ee4e3d9231c5b0c10591f57865e44c192b1880f00000000000000003d6a013504010203040100080000000000aa36a7141f98c06d8734d5a9ff0b53e3294626e62e4d232c14130c4810d57140e1e62967cbf742caeae91b6ecea96898000000000016001450dceca158a9c872eb405d52293d351110572c9e0247304402206e1b1b6869d8720a692a6d861bfe6de20d8a3484a1361dccdb4e8fefdae92fd602202e5bab29d88a45d201696eca86c82bef77a6ebd71878c59738ec685e88d032260121022ae31ea8709aeda8194ba3e2f7e7e95e680e8b65135c8983c0a298d17bc5350a00000000",
            amount: 10000,
        };
        if let Ok(tx) = hex::decode(test_data.tx_hex)
            .map_err(|_| ParserError::InvalidTransactionHex)
            .and_then(|raw_tx| {
                Decodable::consensus_decode(&mut raw_tx.as_slice())
                    .map_err(|_| ParserError::InvalidTransactionHex)
            })
        {
            let vault_row = vault_indexer
                .index_transaction(&tx, 1, String::new(), 0, 0)
                .unwrap();
            assert_eq!(vault_row.info.amount, test_data.amount);
            println!("vault_row: {:?}", vault_row);
        } else {
            println!("Failed to decode tx hex");
        }
    }
}
