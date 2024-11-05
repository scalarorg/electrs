use std::path::Path;
use std::sync::Arc;

use super::db::DBFlush;
use super::{BlockEntry, DBRow, Store, DB};
use crate::chain::{Network, Transaction};

use crate::config::Config;
use crate::util::{bincode_util, full_hash, Bytes, FullHash};
use bitcoin::consensus::Encodable;
use bitcoin::Txid;
use bitcoin_vault::types::{VaultChangeTxOutput, VaultTransaction};
use bitcoin_vault::{DestinationAddress, DestinationChainId, ParsingStaking, StakingParser};
use rayon::prelude::*;

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
    pub destination_chain_id: DestinationChainId,
    pub destination_contract_address: DestinationAddress,
    pub destination_recipient_address: DestinationAddress,
}

impl TxVaultInfo {
    pub fn as_bytes(&self) -> Vec<u8> {
        bincode_util::serialize_big(&self).unwrap()
    }
    pub fn try_from(bytes: &[u8]) -> Result<Self> {
        bincode_util::deserialize_big(bytes)
            .map_err(|e| Error::from(format!("Invalid value: {}", e)))
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct TxVaultKey {
    code: u8,
    height: u32,
    position: u32,
    txid: FullHash,
}
impl TxVaultKey {
    pub fn new(height: u32, position: u32, txid: FullHash) -> Self {
        Self {
            code: b'V',
            height,
            position,
            txid,
        }
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(HASH_LEN + 9);
        bytes.push(self.code);
        for b in self.height.to_be_bytes() {
            bytes.push(b);
        }
        for b in self.position.to_be_bytes() {
            bytes.push(b);
        }
        for b in self.txid {
            bytes.push(b);
        }
        bytes
    }
    pub fn try_from(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HASH_LEN + 8 {
            return Err(Error::from("Invalid length"));
        }
        let height = u32::from_be_bytes(bytes[1..5].try_into().unwrap());
        let position = u32::from_be_bytes(bytes[5..9].try_into().unwrap());
        let txid = full_hash(&bytes[9..]);
        Ok(Self {
            code: b'V',
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
        //Ignore the first byte of the key (b'V')
        let key = TxVaultKey::try_from(&row.key.as_slice()[1..])
            .expect("failed to deserialize TxVaultKey");
        let info =
            bincode_util::deserialize_big(&row.value).expect("failed to deserialize TxVaultInfo");
        TxVaultRow { key, info }
    }

    // pub fn get_txid(&self) -> Result<Txid> {
    //     Txid::from_str(&self.key.txid.as_str()).chain_err(|| "Invalid txid")
    // }
}
impl From<VaultTransaction> for TxVaultInfo {
    fn from(vault_tx: VaultTransaction) -> Self {
        let VaultTransaction {
            txid,
            staker_address,
            staker_pubkey,
            tx_content,
            inputs: _inputs,
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
        TxVaultInfo {
            confirmed_height: 0,
            txid,
            tx_position: 0,
            amount: lock_tx.amount.to_sat(),
            staker_address,
            staker_pubkey,
            tx_content,
            timestamp: 0,
            change_amount,
            change_address,
            destination_chain_id: return_tx.destination_chain_id,
            destination_contract_address: return_tx.destination_contract_address,
            destination_recipient_address: return_tx.destination_recipient_address,
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
        TxVaultInfo::try_from(&value).chain_err(|| "Invalid value")
    }
    pub fn get_lastest_transaction(&self) -> Result<TxVaultInfo> {
        let mut header_it = self.vault_txs.raw_iterator();
        header_it.seek_to_last();
        if header_it.valid() {
            // Get the last header value and deserialize it to get the tx positions
            let value = header_it.value().expect("Failed to get header value");
            TxVaultInfo::try_from(value)
            // let tx_positions: Vec<u16> =
            //     bincode_util::deserialize_big(&value).expect("Failed to deserialize tx positions");

            // if let Some(last_pos) = tx_positions.last() {
            //     // Get the last tx using height and position
            //     let height = header_it.key().expect("Failed to get header key");
            //     let height = u32::from_be_bytes(height.try_into().expect("Invalid height bytes"));

            //     // Construct key to look up the transaction
            //     let key = TxVaultKey::new(height, *last_pos);
            //     let info = self
            //         .vault_txs
            //         .get(key.as_bytes().as_slice())
            //         .and_then(|value| TxVaultInfo::try_from(&value).ok());
            //     return info.ok_or(Error::from("No vault transactions found"));
            // }
        } else {
            Err(Error::from("No vault transactions found"))
        }
    }

    pub fn get_transactions_from_hash(
        &self,
        hash: Option<Vec<u8>>, //hex string
        length: usize,
    ) -> Result<Vec<TxVaultInfo>> {
        let mut tx_vaults = Vec::new();
        let key = hash
            .map(|v| TxVaultKey::try_from(v.as_slice()))
            .transpose()?;
        match key {
            Some(key) => {
                let mut iter = self
                    .vault_txs()
                    .forward_iterator_from(key.as_bytes().as_slice());
                while tx_vaults.len() < length {
                    let Some(Ok((_, value))) = iter.next() else {
                        break;
                    };
                    let tx_vault = TxVaultInfo::try_from(&value)?;
                    tx_vaults.push(tx_vault);
                }
            }

            None => {
                let mut iter = self.vault_txs().raw_iterator();
                iter.seek_to_first();
                while tx_vaults.len() < length && iter.valid() {
                    let Some(value) = iter.value() else {
                        break;
                    };
                    let tx_vault = TxVaultInfo::try_from(&value)?;
                    tx_vaults.push(tx_vault);
                    iter.next();
                }
            }
        };

        Ok(tx_vaults)
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
        match self.staking_parser.parse(tx) {
            Ok(vault_tx) => {
                let mut vault_info = TxVaultInfo::from(vault_tx);
                vault_info.timestamp = block_timestamp;
                vault_info.confirmed_height = confirmed_height;
                vault_info.tx_position = tx_position;
                let vault_key = TxVaultKey::new(
                    confirmed_height,
                    tx_position,
                    full_hash(&vault_info.txid[..]),
                );
                let vault_row = TxVaultRow {
                    key: vault_key,
                    info: vault_info,
                };
                debug!(
                    "Parsed staking transaction: {:?} in block {}",
                    vault_row.info, confirmed_height
                );
                rows.push(vault_row);
            }
            Err(_e) => {
                // Not a staking transaction
                //warn!("Failed to parse staking transaction: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

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
