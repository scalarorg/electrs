use std::str::FromStr;

use super::{BlockEntry, DBRow};
use crate::chain::{Network, Transaction, Txid};
use crate::util::{bincode_util, full_hash, Bytes};
use bitcoin::hex::HexToArrayError;
use bitcoin_vault::types::VaultTransaction;
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

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct TxVaultInfo {
    confirmed_height: u32,
    tx_position: u16,
    amount: u64,
    destination_chain_id: DestinationChainId,
    destination_contract_address: DestinationAddress,
    destination_recipient_address: DestinationAddress,
}

impl TxVaultInfo {}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct TxVaultKey {
    pub code: u8,
    pub txid: String,
}
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct TxVaultRow {
    pub key: TxVaultKey,
    pub info: TxVaultInfo,
}

impl TxVaultRow {
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
        DBRow {
            key: bincode_util::serialize_big(&self.key).unwrap(),
            value: bincode_util::serialize_big(&self.info).unwrap(),
        }
    }

    pub fn from_row(row: DBRow) -> Self {
        let key =
            bincode_util::deserialize_big(&row.key).expect("failed to deserialize TxVaultKey");
        let info =
            bincode_util::deserialize_big(&row.value).expect("failed to deserialize TxVaultInfo");
        TxVaultRow { key, info }
    }

    pub fn get_txid(&self) -> Result<Txid, HexToArrayError> {
        Txid::from_str(&self.key.txid.as_str())
    }
}
impl From<VaultTransaction> for TxVaultRow {
    fn from(vault_tx: VaultTransaction) -> Self {
        let VaultTransaction {
            txid,
            inputs,
            lock_tx,
            return_tx,
            change_tx,
            confirmed_height,
            tx_position,
        } = vault_tx;
        let key = TxVaultKey { code: b'V', txid };
        let info = TxVaultInfo {
            confirmed_height,
            tx_position,
            amount: lock_tx.amount.to_sat(),
            destination_chain_id: return_tx.destination_chain_id,
            destination_contract_address: return_tx.destination_contract_address,
            destination_recipient_address: return_tx.destination_recipient_address,
        };
        TxVaultRow { key, info }
    }
}

pub struct VaultIndexer {
    network: Network,
    tag: Vec<u8>,
    version: u8,
    staking_parser: StakingParser,
}

impl VaultIndexer {
    pub fn new(network: Network, tag: Vec<u8>, version: u8) -> Self {
        let staking_parser = StakingParser::new(tag.clone(), version);
        Self {
            network,
            tag,
            version,
            staking_parser,
        }
    }

    pub fn index_blocks(&self, block_entries: &[BlockEntry]) -> Vec<DBRow> {
        block_entries
            .par_iter() // serialization is CPU-intensive
            .map(|b| {
                let mut rows = vec![];
                for (idx, tx) in b.block.txdata.iter().enumerate() {
                    let height = b.entry.height() as u32;
                    self.index_transaction(tx, height, idx as u16, &mut rows);
                }
                rows
            })
            .flatten()
            .collect()
    }
    fn index_transaction(
        &self,
        tx: &Transaction,
        confirmed_height: u32,
        tx_position: u16,
        rows: &mut Vec<DBRow>,
    ) {
        match self.staking_parser.parse(tx) {
            Ok(mut vault_tx) => {
                vault_tx.confirmed_height = confirmed_height;
                vault_tx.tx_position = tx_position;
                debug!(
                    "Parsed staking transaction: {:?} in block {}",
                    vault_tx, confirmed_height
                );
                let vault_row = TxVaultRow::from(vault_tx);
                rows.push(vault_row.into_row());
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
    use bitcoin::consensus::Decodable;
    use bitcoin_vault::types::error::ParserError;

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
        let vault_indexer = VaultIndexer::new(Network::Testnet4, tag, version);
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
            vault_indexer.index_transaction(&tx, 1, 0, &mut rows);
            assert_eq!(rows.len(), 1);
            let vault_row = TxVaultRow::from_row(rows.pop().unwrap());
            assert_eq!(vault_row.info.amount, test_data.amount);
            println!("vault_row: {:?}", vault_row);
        } else {
            println!("Failed to decode tx hex");
        }
    }
}
