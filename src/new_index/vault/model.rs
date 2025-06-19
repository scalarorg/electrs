use super::DBRow;
use crate::chain::BlockHash;
use crate::errors::*;
use crate::util::{bincode_util, full_hash, Bytes};
use bitcoin::consensus::Encodable;
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::Txid;
use bitcoin_vault::{
    types::{VaultChangeTxOutput, VaultReturnTxOutputType, VaultTransaction},
    SERVICE_TAG_HASH_SIZE,
};
use serde_json::Value;

const HASH_LEN: usize = 32;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxVaultInfo {
    pub confirmed_height: u32,
    pub block_hash: String,
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
    pub session_sequence: u64,
    pub custodian_group_uid: [u8; HASH_LEN],
    pub script_pubkey: Vec<u8>,
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
            outputs,
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
            VaultReturnTxOutputType::Unlocking => 2_u8,
            VaultReturnTxOutputType::Locking => 1_u8,
        };
        let script_pubkey = outputs
            .get(1)
            .map(|output| output.script_pubkey.to_bytes())
            .unwrap_or_default();
        TxVaultInfo {
            confirmed_height: 0,
            block_hash: "".to_string(),
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
            session_sequence: return_tx.session_sequence,
            custodian_group_uid: return_tx.custodian_group_uid,
            script_pubkey,
        }
    }
}

pub struct BlockVaultTxs {
    pub hash: BlockHash,
    pub vault_txs: Vec<TxVaultRow>,
}
impl BlockVaultTxs {
    pub fn new(hash: BlockHash) -> Self {
        Self {
            hash,
            vault_txs: vec![],
        }
    }
    pub fn add_tx(&mut self, tx: TxVaultRow) {
        self.vault_txs.push(tx);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultTxHeader {
    pub txid: Txid,
    pub pos: u32,
    pub sender_address: Option<String>,
    pub sender_pubkey: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockVaultRow {
    pub height: usize,
    pub hash: BlockHash,
    pub tx_headers: Vec<VaultTxHeader>,
}
impl BlockVaultRow {
    pub fn into_row(self) -> DBRow {
        DBRow {
            key: self.hash.as_byte_array().to_vec(),
            value: bincode_util::serialize_big(&self).unwrap(),
        }
    }

    pub fn from_row(row: DBRow) -> Self {
        let block_vault_row =
            bincode_util::deserialize_big(&row.value).expect("failed to deserialize BlockVaultRow");
        block_vault_row
    }
    pub fn try_from_bytes(_key: &[u8], value: &[u8]) -> Result<Self> {
        // let _hash = BlockHash::from_slice(_key).unwrap();
        let block_vault_row =
            bincode_util::deserialize_big(value).expect("failed to deserialize BlockVaultRow");
        Ok(block_vault_row)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultTxValue {
    pub raw_tx: Vec<u8>,
    pub txid: Txid,
    pub sender_address: Option<String>,
    pub sender_pubkey: Option<String>,
    pub pos: u32,
    pub proof: Vec<sha256d::Hash>,
}
impl From<&VaultTxValue> for Value {
    fn from(value: &VaultTxValue) -> Self {
        json!(value)
        // json!({
        //     "raw_tx": value.raw_tx,
        //     "txid": value.txid,
        //     "sender": value.sender,
        //     "pos": value.pos,
        //     "proof": value.proof,
        // })
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultBlockValue {
    pub hash: BlockHash,
    pub txes: Vec<VaultTxValue>,
}

impl From<&VaultBlockValue> for Value {
    fn from(value: &VaultBlockValue) -> Self {
        json!({
            "hash": value.hash,
            "txes": value.txes.iter().map(|tx| tx.into()).collect::<Vec<Value>>(),
        })
    }
}
#[cfg(test)]
mod tests {
    use bitcoin::consensus::Decodable;
    use bitcoin_vault::ParsingStaking;
    use bitcoin_vault::{types::error::ParserError, StakingParser};
    use std::str::FromStr;

    use crate::{chain::Network, util::ScriptToAddr};

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
    fn test_parse_vault_tx() {
        let tag = "SCALAR".as_bytes().to_vec();
        let version = 3;
        let staking_parser = StakingParser::new(tag.clone(), version);
        let test_data = TestData {
            tx_hex: "02000000000102efb8da1b0ae26ab9b7b25c5f044d5b02684d5471c77d6e1f08de98b1501f6d576300000000ffffffffedae00f4acb83258db5c03e638864cf131ee6997a96f65fb8d7792ad9d3138636300000000ffffffff030000000000000000416a3f5343414c4152030140706f6f6c73030100000000aa36a72ca3698a551a57169e73b0b2566a106ddec1b7b6913560c5613a1f56cedb44e338441968cea824950d26000000000000225120a8fc50d87f16d892b4d4d087d259c0ab417e106b044b291a7728d2ae1343de7f0b860100000000001600143f80b86ad8975ec3db0299f8d637cf3e678a23ab024830450221009c9bac187d97243444ee30a6febb2d8850554aa08a23345cc1b0ef2112f8e9830220394df5439ad77eda57fbd51121987aaff563c92321e5502b7c47ba79b8ffa677012102ddd45dd5601e1c0d56ccc065817d363f008840b8a7ab1f0f3cb17636aad9dfca0247304402203b61cc79d519f0308f8a260b66c250bce14be86cb33da396ae5d73a252dbd46102200644d2c7a8847d02da3631dce2ffabb0833ed1371c14a43e517e0135b7cf9e12012102ddd45dd5601e1c0d56ccc065817d363f008840b8a7ab1f0f3cb17636aad9dfca00000000",
            amount: 10000,
        };
        if let Ok(tx) = hex::decode(test_data.tx_hex)
            .map_err(|_| ParserError::InvalidTransactionHex)
            .and_then(|raw_tx| {
                Decodable::consensus_decode(&mut raw_tx.as_slice())
                    .map_err(|_| ParserError::InvalidTransactionHex)
            })
        {
            let res = staking_parser.parse(&tx);
            println!("res: {:?}", res);
            assert!(res.is_ok(), "Failed to parse vault tx");
            let vault_tx = res.unwrap();
            assert!(vault_tx.outputs.len() > 1);
            let second_output = vault_tx.outputs.get(1).unwrap();
            let script_pubkey = &second_output.script_pubkey;
            assert_eq!(
                "5120a8fc50d87f16d892b4d4d087d259c0ab417e106b044b291a7728d2ae1343de7f",
                script_pubkey.to_hex_string()
            );
            let address = script_pubkey.to_address_str(Network::Testnet4);
            println!("address: {:?}", address);
        }
    }
}
