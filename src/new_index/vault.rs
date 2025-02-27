use std::path::Path;
use std::sync::Arc;

use super::db::DBFlush;
use super::schema::lookup_txo;
use super::{BlockEntry, DBRow, Store, DB};
use crate::chain::{Network, Transaction};

use crate::config::Config;
use crate::util::{bincode_util, full_hash, Bytes, ScriptToAddr};
use bitcoin::consensus::Encodable;
use bitcoin::hashes::Hash;
use bitcoin::{OutPoint, ScriptBuf, TxIn, TxOut, Txid};
use bitcoin_vault::{
    types::{VaultChangeTxOutput, VaultReturnTxOutputType, VaultTransaction},
    SERVICE_TAG_HASH_SIZE,
};
use bitcoin_vault::{ParsingStaking, StakingParser};
use rayon::prelude::*;
use serde_json::Value;

#[cfg(feature = "liquid")]
use crate::elements::{asset, peg};
#[cfg(not(feature = "liquid"))]
use bitcoin::consensus::encode::{deserialize, serialize};
#[cfg(feature = "liquid")]
use elements::{
    encode::{deserialize, serialize},
    AssetId,
};

use crate::errors::*;

const HASH_LEN: usize = 32;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxVaultInfo {
    pub confirmed_height: u32,
    pub txid: Txid,
    pub tx_position: u32,
    pub amount: u64,
    pub staker_address: Option<String>,
    pub staker_pubkey: Option<String>,
    // the Hex content of the transaction
    pub tx_content: String,
    pub timestamp: u32,
    pub change_amount: Option<u64>,
    pub change_address: Option<String>,
    pub service_tag: [u8; SERVICE_TAG_HASH_SIZE],
    pub covenant_quorum: u8,
    pub vault_tx_type: u8, //1.Staking, 2.Unstaking
    // Destination chain family(1 byte) and id(7 bytes)
    pub destination_chain: u64,
    pub destination_token_address: String,     //Hex string
    pub destination_recipient_address: String, //Hex string
}

impl TxVaultInfo {
    pub fn as_bytes(&self) -> Vec<u8> {
        bincode_util::serialize_big(&self).unwrap()
    }
    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode_util::deserialize_big(bytes)
            .map_err(|e| Error::from(format!("Invalid value: {}", e)))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxVaultKey {
    pub height: u32,
    pub position: u32,
    pub txid: Txid,
}
impl TxVaultKey {
    pub fn new(height: u32, position: u32, txid: Txid) -> Self {
        Self {
            height,
            position,
            //txid: full_hash(&txid[..]),
            txid,
        }
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(HASH_LEN + 8);
        for b in self.height.to_be_bytes() {
            bytes.push(b);
        }
        for b in self.position.to_be_bytes() {
            bytes.push(b);
        }
        for b in self.txid.as_raw_hash().as_byte_array() {
            bytes.push(*b);
        }
        bytes
    }
    pub fn as_hex(&self) -> String {
        hex::encode(self.as_bytes())
    }
    pub fn try_from_hex(hex: &str) -> Result<Self> {
        let bytes = hex::decode(hex).map_err(|e| Error::from(e.to_string()))?;
        Self::try_from_bytes(bytes.as_slice())
    }
    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HASH_LEN + 8 {
            error!("Invalid length: {:?}", bytes.len());
            return Err(Error::from("Invalid length"));
        }
        let height = u32::from_be_bytes(bytes[0..4].try_into().unwrap());
        let position = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
        let txid = Txid::from_slice(&bytes[8..]).map_err(|e| Error::from(e.to_string()))?;
        //let txid = full_hash(&bytes[8..]);
        Ok(Self {
            height,
            position,
            txid,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxVaultRow {
    pub key: TxVaultKey,
    pub info: TxVaultInfo,
}

impl TxVaultRow {
    fn new(key: TxVaultKey, info: TxVaultInfo) -> Self {
        Self { key, info }
    }
    fn filter(code: u8, hash_prefix: &[u8]) -> Bytes {
        [&[code], hash_prefix].concat()
    }

    fn prefix_end(code: u8, hash: &[u8]) -> Bytes {
        bincode_util::serialize_big(&(code, full_hash(hash), u32::MAX)).unwrap()
    }

    fn prefix_height(code: u8, hash: &[u8], height: u32) -> Bytes {
        bincode_util::serialize_big(&(code, full_hash(hash), height)).unwrap()
    }

    // prefix representing the end of a given block (used for reverse scans)
    fn prefix_height_end(code: u8, hash: &[u8], height: u32) -> Bytes {
        // u16::MAX for the tx_position ensures we get all transactions at this height
        bincode_util::serialize_big(&(code, full_hash(hash), height, u16::MAX)).unwrap()
    }

    pub fn into_row(self) -> DBRow {
        let TxVaultRow { key, info } = self;
        DBRow {
            key: key.as_bytes(),
            value: info.as_bytes(),
        }
    }

    pub fn from_row(row: DBRow) -> Self {
        let key = TxVaultKey::try_from_bytes(row.key.as_slice())
            .expect("failed to deserialize TxVaultKey");
        let info =
            bincode_util::deserialize_big(&row.value).expect("failed to deserialize TxVaultInfo");
        TxVaultRow { key, info }
    }
    pub fn try_from_bytes(key: &[u8], value: &[u8]) -> Result<Self> {
        let key = TxVaultKey::try_from_bytes(key)?;
        let info = TxVaultInfo::try_from_bytes(value)?;
        Ok(TxVaultRow { key, info })
    }
    // pub fn get_txid(&self) -> Result<Txid> {
    //     Txid::from_str(&self.key.txid.as_str()).chain_err(|| "Invalid txid")
    // }
}
impl From<&TxVaultRow> for Value {
    fn from(value: &TxVaultRow) -> Self {
        let mut result = json!(&value.info);
        result
            .as_object_mut()
            .unwrap()
            .insert("key".to_string(), value.key.as_hex().into());
        result
    }
}
impl From<VaultTransaction> for TxVaultInfo {
    fn from(vault_tx: VaultTransaction) -> Self {
        let VaultTransaction {
            txid,
            tx_content,
            inputs,
            lock_tx,
            return_tx,
            change_tx,
        } = vault_tx;
        let mut writer = vec![];
        txid.consensus_encode(&mut writer).unwrap();
        //let key = TxVaultKey::new(full_hash(&txid[..]));
        let (change_amount, change_address) =
            if let Some(VaultChangeTxOutput { amount, address }) = change_tx {
                (Some(amount.to_sat()), Some(address))
            } else {
                (None, None)
            };
        let vault_tx_type = match return_tx.transaction_type {
            VaultReturnTxOutputType::Unstaking => 2_u8,
            VaultReturnTxOutputType::Staking => 1_u8,
        };
        TxVaultInfo {
            confirmed_height: 0,
            txid,
            tx_position: 0,
            amount: {
                if let Some(lock_tx) = lock_tx {
                    lock_tx.amount.to_sat()
                } else {
                    0
                }
            },
            staker_address: None,
            staker_pubkey: None,
            tx_content,
            timestamp: 0,
            change_amount,
            change_address,
            vault_tx_type,
            service_tag: return_tx.service_tag,
            covenant_quorum: return_tx.custodian_quorum,
            destination_chain: u64::from_be_bytes(return_tx.destination_chain),
            destination_token_address: hex::encode(return_tx.destination_token_address),
            destination_recipient_address: hex::encode(return_tx.destination_recipient_address),
        }
    }
}
pub struct VaultStore {
    vault_txs: DB, //Store map TxVaultKey to TxVaultInfo
                   // vault_headers: DB, //Store map BlockHeight to list of tx positions if has any
}
impl VaultStore {
    pub fn open(path: &Path, config: &Config) -> Self {
        let vault_txs = DB::open(&path.join("vaulttxs"), config);
        // let vault_headers = DB::open(&path.join("vaultheader"), config);
        Self { vault_txs }
    }
    pub fn vault_txs(&self) -> &DB {
        &self.vault_txs
    }
    // pub fn vault_headers(&self) -> &DB {
    //     &self.vault_headers
    // }
    pub fn flush_vault_tx(&self, vault_rows: Vec<DBRow>) {
        self.vault_txs.write(vault_rows, DBFlush::Enable);
    }
    pub fn get_vault_info(&self, key: &TxVaultKey) -> Result<TxVaultInfo> {
        let key = key.as_bytes();
        let value = self
            .vault_txs
            .get(key.as_slice())
            .chain_err(|| "TxVault not found")?;
        TxVaultInfo::try_from_bytes(&value).chain_err(|| "Invalid value")
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
        let vault_rows: Vec<TxVaultRow> = block_entries
            .par_iter() // serialization is CPU-intensive
            .map(|b| {
                let mut rows = vec![];
                for (idx, tx) in b.block.txdata.iter().enumerate() {
                    let height = b.entry.height() as u32;
                    let block_timestamp = b.entry.header().time;
                    self.index_transaction(tx, height, idx as u32, block_timestamp, &mut rows);
                }
                rows
            })
            .flatten()
            .collect();

        if !vault_rows.is_empty() {
            //Reorder the rows by height and tx_position
            //vault_rows.par_sort_by_key(|row| (row.info.confirmed_height, row.info.tx_position));
            let dbrows = vault_rows.into_iter().map(|tx| tx.into_row()).collect();
            let vault_store = self.store.vault_store();
            vault_store.flush_vault_tx(dbrows);
            // Check insert order
            // let mut iter = vault_store.vault_txs().raw_iterator();
            // iter.seek_to_first();
            // while iter.valid() {
            //     let Some(value) = iter.value() else {
            //         break;
            //     };
            //     if let Ok(tx_vault) = TxVaultInfo::try_from(&value) {
            //         debug!("tx_vault: {:?}", tx_vault);
            //     };
            //     iter.next();
            // }
        }
    }
    fn index_transaction(
        &self,
        tx: &Transaction,
        confirmed_height: u32,
        tx_position: u32,
        block_timestamp: u32,
        rows: &mut Vec<TxVaultRow>,
    ) {
        //Todo: Set staker address and pubkey by first txin
        match self.staking_parser.parse(tx) {
            Ok(vault_tx) => {
                let first_txin = vault_tx.inputs.first();
                let staker_pubkey = self.extract_script_pubkey(first_txin);
                let staker_address = self.extract_staker_address(first_txin);
                //let script_pubkey = first_txin.and_then(|input| input.get_pubkey());
                let mut vault_info = TxVaultInfo::from(vault_tx);
                vault_info.timestamp = block_timestamp;
                vault_info.confirmed_height = confirmed_height;
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
                rows.push(vault_row);
            }
            Err(_e) => {
                // Not a staking transaction
                //warn!("Failed to parse staking transaction: {}", e);
            }
        }
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
    use std::{path::PathBuf, str::FromStr};

    use bitcoin::consensus::Decodable;
    use bitcoin_vault::types::error::ParserError;

    use crate::config::Config;

    use super::*;
    #[derive(Debug)]
    struct TestData<'a> {
        tx_hex: &'a str,
        amount: u64,
    }
    #[test]
    fn test_vault_key() {
        let txid_str = "2e262c1986f7ca376842ec976283f22f28ebfda19db223b569f87bed1ea927dd";
        let txid = Txid::from_str(txid_str).unwrap();
        println!("txid: {:?}", txid);
        let hash =
            "0000d1d900000005dd27a91eed7bf869b523b29da1fdeb282ff2836297ec426837caf786192c262e";
        let expected_key = TxVaultKey::new(53721, 5, txid);
        let parsed_key = TxVaultKey::try_from_hex(hash).unwrap();
        println!("Parsed key: {:?}", parsed_key);
        println!("Expected key: {:?}", expected_key);
        assert_eq!(parsed_key.as_hex(), hash);
    }
    #[test]
    fn test_vault_indexer_testnet4() {
        let tag = hex::decode("01020304").unwrap();
        let version = 0;
        let staking_parser = StakingParser::new(tag.clone(), version);
        let config = create_test_config();
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
            let mut rows = vec![];
            vault_indexer.index_transaction(&tx, 1, 0, 0, &mut rows);
            assert_eq!(rows.len(), 1);
            let vault_row = rows.pop().unwrap();
            assert_eq!(vault_row.info.amount, test_data.amount);
            println!("vault_row: {:?}", vault_row);
        } else {
            println!("Failed to decode tx hex");
        }
    }

    fn create_test_config() -> Config {
        Config::from_args()
    }
}
