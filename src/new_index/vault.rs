use super::{compute_script_hash, DBRow};
use crate::chain::{OutPoint, Transaction, TxOut, Txid, Value};
use crate::util::{bincode_util, full_hash, has_prevout, is_spendable, Bytes, FullHash};
use bitcoin::blockdata::opcodes::all as opcodes;
use bitcoin::blockdata::script::Instruction;
use bitcoin::ScriptBuf;
use bitcoin::{Block, Network};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::str::FromStr;

#[cfg(feature = "liquid")]
use crate::elements::{asset, peg};
#[cfg(not(feature = "liquid"))]
use bitcoin::consensus::encode::{deserialize, serialize};
#[cfg(feature = "liquid")]
use elements::{
    encode::{deserialize, serialize},
    AssetId,
};

#[derive(Serialize, Deserialize, Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct FundingInfo {
    pub txid: FullHash,
    pub vout: u32,
    pub value: Value,
}

#[derive(Serialize, Deserialize, Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct SpendingInfo {
    pub txid: FullHash, // spending transaction
    pub vin: u32,
    pub prev_txid: FullHash, // funding transaction
    pub prev_vout: u32,
    pub value: Value,
}

#[derive(Serialize, Deserialize, Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub enum TxVaultInfo {
    // If a spend and a fund for the same scripthash
    // occur in the same tx, spends should come first.
    // This ordering comes from the enum order.
    Spending(SpendingInfo),
    Funding(FundingInfo),

    #[cfg(feature = "liquid")]
    Issuing(asset::IssuingInfo),
    #[cfg(feature = "liquid")]
    Burning(asset::BurningInfo),
    #[cfg(feature = "liquid")]
    Pegin(peg::PeginInfo),
    #[cfg(feature = "liquid")]
    Pegout(peg::PegoutInfo),
}

impl TxVaultInfo {
    pub fn get_txid(&self) -> Txid {
        match self {
            TxVaultInfo::Funding(FundingInfo { txid, .. })
            | TxVaultInfo::Spending(SpendingInfo { txid, .. }) => deserialize(txid),

            #[cfg(feature = "liquid")]
            TxVaultInfo::Issuing(asset::IssuingInfo { txid, .. })
            | TxVaultInfo::Burning(asset::BurningInfo { txid, .. })
            | TxVaultInfo::Pegin(peg::PeginInfo { txid, .. })
            | TxVaultInfo::Pegout(peg::PegoutInfo { txid, .. }) => deserialize(txid),
        }
        .expect("cannot parse Txid")
    }
    // for funding rows, returns the funded output.
    // for spending rows, returns the spent previous output.
    pub fn get_funded_outpoint(&self) -> OutPoint {
        match self {
            TxVaultInfo::Funding(ref info) => OutPoint {
                txid: deserialize(&info.txid).unwrap(),
                vout: info.vout,
            },
            TxVaultInfo::Spending(ref info) => OutPoint {
                txid: deserialize(&info.prev_txid).unwrap(),
                vout: info.prev_vout,
            },
            #[cfg(feature = "liquid")]
            TxVaultInfo::Issuing(_)
            | TxVaultInfo::Burning(_)
            | TxVaultInfo::Pegin(_)
            | TxVaultInfo::Pegout(_) => unreachable!(),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct TxVaultKey {
    pub code: u8,              // H for script history or I for asset history (elements only)
    pub hash: FullHash, // either a scripthash (always on bitcoin) or an asset id (elements only)
    pub confirmed_height: u32, // MUST be serialized as big-endian (for correct scans).
    pub tx_position: u16, // MUST be serialized as big-endian (for correct scans). Position in block.
    pub txinfo: TxVaultInfo,
}

pub struct TxVaultRow {
    pub key: TxVaultKey,
}

impl TxVaultRow {
    fn new(
        script: &ScriptBuf,
        confirmed_height: u32,
        tx_position: u16,
        txinfo: TxVaultInfo,
    ) -> Self {
        let key = TxVaultKey {
            code: b'H',
            hash: compute_script_hash(script),
            confirmed_height,
            tx_position,
            txinfo,
        };
        TxVaultRow { key }
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
        DBRow {
            key: bincode_util::serialize_big(&self.key).unwrap(),
            value: vec![],
        }
    }

    pub fn from_row(row: DBRow) -> Self {
        let key =
            bincode_util::deserialize_big(&row.key).expect("failed to deserialize TxVaultKey");
        TxVaultRow { key }
    }

    pub fn get_txid(&self) -> Txid {
        self.key.txinfo.get_txid()
    }
    fn get_funded_outpoint(&self) -> OutPoint {
        self.key.txinfo.get_funded_outpoint()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultState {
    pub vault_id: String,
    pub owner: String,
    pub balance: u64,
    pub status: VaultStatus,
    // pub created_at: DateTime<Utc>,
    // pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VaultStatus {
    Active,
    Closed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultTransaction {
    pub tx_hash: String,
    pub vault_id: String,
    pub amount: i64,
    pub tx_type: VaultTxType,
    pub block_height: u32,
    // pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VaultTxType {
    Deposit,
    Withdraw,
    Create,
    Close,
}

pub struct VaultIndexer {
    vaults: HashMap<String, VaultState>,
    vault_txs: Vec<VaultTransaction>,
    utxo_set: HashMap<OutPoint, (String, u64)>, // (vault_id, amount)
    network: Network,
}

impl VaultIndexer {
    pub fn new(network: Network) -> Self {
        Self {
            vaults: HashMap::new(),
            vault_txs: Vec::new(),
            utxo_set: HashMap::new(),
            network,
        }
    }

    // pub fn index_block(&mut self, block: &Block) {
    //     let block_height = block.bip34_block_height().unwrap_or(0);
    //     let timestamp = DateTime::<Utc>::from_utc(
    //         chrono::NaiveDateTime::from_timestamp_opt(block.header.time as i64, 0).unwrap(),
    //         Utc,
    //     );

    //     for tx in &block.txdata {
    //         self.process_transaction(tx, block_height, timestamp);
    //     }
    // }

    // fn process_transaction(
    //     &mut self,
    //     tx: &Transaction,
    //     block_height: u32,
    //     timestamp: DateTime<Utc>,
    // ) {
    //     let tx_hash = tx.txid().to_string();

    //     // Process inputs
    //     for input in &tx.input {
    //         if let Some((vault_id, amount)) = self.utxo_set.remove(&input.previous_output) {
    //             self.update_vault_balance(&vault_id, -(amount as i64), timestamp);
    //             self.add_vault_tx(
    //                 &tx_hash,
    //                 &vault_id,
    //                 -(amount as i64),
    //                 VaultTxType::Withdraw,
    //                 block_height,
    //                 timestamp,
    //             );
    //         }
    //     }

    //     // Process outputs
    //     for (vout, output) in tx.output.iter().enumerate() {
    //         if let Some(vault_op) = self.parse_vault_operation(&output.script_pubkey) {
    //             match vault_op {
    //                 VaultOperation::Create(vault_id, owner) => {
    //                     self.create_vault(&vault_id, &owner, timestamp);
    //                     self.add_vault_tx(
    //                         &tx_hash,
    //                         &vault_id,
    //                         output.value as i64,
    //                         VaultTxType::Create,
    //                         block_height,
    //                         timestamp,
    //                     );
    //                 }
    //                 VaultOperation::Deposit(vault_id) => {
    //                     self.update_vault_balance(&vault_id, output.value as i64, timestamp);
    //                     self.add_vault_tx(
    //                         &tx_hash,
    //                         &vault_id,
    //                         output.value as i64,
    //                         VaultTxType::Deposit,
    //                         block_height,
    //                         timestamp,
    //                     );
    //                 }
    //                 VaultOperation::Withdraw(vault_id) => {
    //                     // Withdrawal amount is handled in input processing
    //                     // Here we just record the transaction
    //                     self.add_vault_tx(
    //                         &tx_hash,
    //                         &vault_id,
    //                         0,
    //                         VaultTxType::Withdraw,
    //                         block_height,
    //                         timestamp,
    //                     );
    //                 }
    //                 VaultOperation::Close(vault_id) => {
    //                     self.close_vault(&vault_id, timestamp);
    //                     self.add_vault_tx(
    //                         &tx_hash,
    //                         &vault_id,
    //                         0,
    //                         VaultTxType::Close,
    //                         block_height,
    //                         timestamp,
    //                     );
    //                 }
    //             }
    //             self.utxo_set.insert(
    //                 OutPoint::new(tx.txid(), vout as u32),
    //                 (vault_id.clone(), output.value),
    //             );
    //         }
    //     }
    // }

    // fn update_vault_balance(&mut self, vault_id: &str, amount: i64, timestamp: DateTime<Utc>) {
    //     if let Some(vault) = self.vaults.get_mut(vault_id) {
    //         vault.balance = (vault.balance as i64 + amount) as u64;
    //         vault.updated_at = timestamp;
    //     }
    // }

    // fn add_vault_tx(
    //     &mut self,
    //     tx_hash: &str,
    //     vault_id: &str,
    //     amount: i64,
    //     tx_type: VaultTxType,
    //     block_height: u32,
    //     timestamp: DateTime<Utc>,
    // ) {
    //     self.vault_txs.push(VaultTransaction {
    //         tx_hash: tx_hash.to_string(),
    //         vault_id: vault_id.to_string(),
    //         amount,
    //         tx_type,
    //         block_height,
    //         timestamp,
    //     });
    // }

    // fn create_vault(&mut self, vault_id: &str, owner: &str, timestamp: DateTime<Utc>) {
    //     let vault = VaultState {
    //         vault_id: vault_id.to_string(),
    //         owner: owner.to_string(),
    //         balance: 0,
    //         status: VaultStatus::Active,
    //         created_at: timestamp,
    //         updated_at: timestamp,
    //     };
    //     self.vaults.insert(vault_id.to_string(), vault);
    // }

    // fn close_vault(&mut self, vault_id: &str, timestamp: DateTime<Utc>) {
    //     if let Some(vault) = self.vaults.get_mut(vault_id) {
    //         vault.status = VaultStatus::Closed;
    //         vault.updated_at = timestamp;
    //     }
    // }

    // fn parse_vault_operation(&self, script: &Script) -> Option<VaultOperation> {
    //     let mut instructions = script.instructions();

    //     // Check for OP_RETURN
    //     match instructions.next() {
    //         Some(Ok(Instruction::Op(opcodes::OP_RETURN))) => {}
    //         _ => return None,
    //     }

    //     // Parse the vault operation type
    //     let op_type = match instructions.next() {
    //         Some(Ok(Instruction::PushBytes(bytes))) if bytes.len() == 1 => bytes[0],
    //         _ => return None,
    //     };

    //     match op_type {
    //         0x01 => self.parse_create_vault(&mut instructions),
    //         0x02 => self.parse_deposit_vault(&mut instructions),
    //         0x03 => self.parse_withdraw_vault(&mut instructions),
    //         0x04 => self.parse_close_vault(&mut instructions),
    //         _ => None,
    //     }
    // }

    // fn parse_create_vault(
    //     &self,
    //     instructions: &mut std::iter::Enumerate<bitcoin::blockdata::script::Instructions>,
    // ) -> Option<VaultOperation> {
    //     let vault_id = self.parse_vault_id(instructions)?;
    //     let owner = self.parse_address(instructions)?;
    //     Some(VaultOperation::Create(vault_id, owner))
    // }

    fn parse_deposit_vault(
        &self,
        instructions: &mut std::iter::Enumerate<bitcoin::blockdata::script::Instructions>,
    ) -> Option<VaultOperation> {
        let vault_id = self.parse_vault_id(instructions)?;
        Some(VaultOperation::Deposit(vault_id))
    }

    fn parse_withdraw_vault(
        &self,
        instructions: &mut std::iter::Enumerate<bitcoin::blockdata::script::Instructions>,
    ) -> Option<VaultOperation> {
        let vault_id = self.parse_vault_id(instructions)?;
        Some(VaultOperation::Withdraw(vault_id))
    }

    fn parse_close_vault(
        &self,
        instructions: &mut std::iter::Enumerate<bitcoin::blockdata::script::Instructions>,
    ) -> Option<VaultOperation> {
        let vault_id = self.parse_vault_id(instructions)?;
        Some(VaultOperation::Close(vault_id))
    }

    fn parse_vault_id(
        &self,
        instructions: &mut std::iter::Enumerate<bitcoin::blockdata::script::Instructions>,
    ) -> Option<String> {
        match instructions.next() {
            Some((_, Ok(Instruction::PushBytes(bytes)))) if bytes.len() == 32 => {
                Some(hex::encode(bytes))
            }
            _ => None,
        }
    }

    // fn parse_address(
    //     &self,
    //     instructions: &mut std::iter::Enumerate<bitcoin::blockdata::script::Instructions>,
    // ) -> Option<String> {
    //     match instructions.next() {
    //         Some((_, Ok(Instruction::PushBytes(bytes)))) => {
    //             bitcoin::Address::from_script(&Script::from_bytes(bytes), self.network)
    //                 .map(|addr| addr.to_string())
    //                 .ok()
    //         }
    //         _ => None,
    //     }
    // }

    // ... (keep other existing methods) ...
}

enum VaultOperation {
    Create(String, String), // (vault_id, owner)
    Deposit(String),        // vault_id
    Withdraw(String),       // vault_id
    Close(String),          // vault_id
}

pub(super) fn try_index_transaction(
    tx: &Transaction,
    confirmed_height: u32,
    tx_position: u16,
    rows: &mut Vec<DBRow>,
) {
    debug!("Try Indexing vault transaction");
    // persist history index:
    //      H{funding-scripthash}{spending-height}{spending-block-pos}S{spending-txid:vin}{funding-txid:vout} → ""
    //      H{funding-scripthash}{funding-height}{funding-block-pos}F{funding-txid:vout} → ""
    // persist "edges" for fast is-this-TXO-spent check
    //      S{funding-txid:vout}{spending-txid:vin} → ""
    let txid = full_hash(&tx.txid()[..]);
    for (txo_index, txo) in tx.output.iter().enumerate() {
        // if is_spendable(txo) || iconfig.index_unspendables {
        //     let history = TxVaultRow::new(
        //         &txo.script_pubkey,
        //         confirmed_height,
        //         tx_position,
        //         TxVaultInfo::Funding(FundingInfo {
        //             txid,
        //             vout: txo_index as u32,
        //             value: txo.value,
        //         }),
        //     );
        //     rows.push(history.into_row());

        //     if iconfig.address_search {
        //         if let Some(row) = addr_search_row(&txo.script_pubkey, iconfig.network) {
        //             rows.push(row);
        //         }
        //     }
        // }
    }
    for (txi_index, txi) in tx.input.iter().enumerate() {
        if !has_prevout(txi) {
            continue;
        }
        // let prev_txo = previous_txos_map.get(&txi.previous_output);
        // if prev_txo.is_none() && !iconfig.allow_missing {
        //     panic!("missing previous txo {}", txi.previous_output);
        // };
        // let empty_script = Script::new();
        // let history = TxVaultRow::new(
        //     prev_txo.map_or(&empty_script, |txo| &txo.script_pubkey),
        //     confirmed_height,
        //     tx_position,
        //     TxVaultInfo::Spending(SpendingInfo {
        //         txid,
        //         vin: txi_index as u32,
        //         prev_txid: full_hash(&txi.previous_output.txid[..]),
        //         prev_vout: txi.previous_output.vout,
        //         value: prev_txo.map_or(0, |txo| txo.value),
        //     }),
        // );
        // rows.push(history.into_row());

        // let edge = TxEdgeRow::new(
        //     full_hash(&txi.previous_output.txid[..]),
        //     txi.previous_output.vout,
        //     txid,
        //     txi_index as u32,
        // );
        // rows.push(edge.into_row());
    }

    // Index issued assets & native asset pegins/pegouts/burns
    // #[cfg(feature = "liquid")]
    // asset::index_confirmed_tx_assets(
    //     tx,
    //     confirmed_height,
    //     tx_position,
    //     iconfig.network,
    //     iconfig.parent_network,
    //     rows,
    // );
}

#[cfg(all(test, feature = "liquid"))]
mod tests {
    use super::{DBRow, TxVaultRow};
    use crate::chain::Value;
    use std::convert::TryInto;

    #[test]
    fn tx_vault() {
        #[rustfmt::skip]
        let inputs = [
            vec![
                // code
                72,
                // hash
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                   1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                // confirmed_height
                0, 0, 0, 2,
                // tx_position
                0, 3,
                // TxVaultInfo variant (Funding)
                0, 0, 0, 1,
                // FundingInfo
                // txid
                2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
                   2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
                // vout
                0, 0, 0, 3,
                // Value variant (Explicit)
                0, 0, 0, 0, 0, 0, 0, 2,
                // number of tuple elements
                1,
                // Inner value (u64)
                7, 0, 0, 0, 0, 0, 0, 0,
            ],
            vec![
                72,
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                   1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                0, 0, 0, 2,
                0, 3,
                0, 0, 0, 1,
                2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
                   2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
                0, 0, 0, 3,
                // Value variant (Null)
                0, 0, 0, 0, 0, 0, 0, 1,
                // number of tuple elements
                0,
            ],
            vec![
                72,
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                   1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                0, 0, 0, 2,
                0, 3,
                0, 0, 0, 0,
                18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18,
                    18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18,
                0, 0, 0, 12,
                98, 101, 101, 102, 98, 101, 101, 102, 98, 101, 101, 102, 98, 101, 101, 102,
                    98, 101, 101, 102, 98, 101, 101, 102, 98, 101, 101, 102, 98, 101, 101, 102,
                0, 0, 0, 9,
                0, 0, 0, 0, 0, 0, 0, 2,
                1,
                14, 0, 0, 0, 0, 0, 0, 0,
            ],
            vec![
                72,
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                   1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                0, 0, 0, 2,
                0, 3,
                0, 0, 0, 0,
                18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18,
                    18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18,
                0, 0, 0, 12,
                98, 101, 101, 102, 98, 101, 101, 102, 98, 101, 101, 102, 98, 101, 101, 102,
                    98, 101, 101, 102, 98, 101, 101, 102, 98, 101, 101, 102, 98, 101, 101, 102,
                0, 0, 0, 9,
                0, 0, 0, 0, 0, 0, 0, 1,
                0,
            ],
        ];
        let expected = [
            super::TxVaultRow {
                key: super::TxVaultKey {
                    code: b'H',
                    hash: [1; 32],
                    confirmed_height: 2,
                    tx_position: 3,
                    txinfo: super::TxVaultInfo::Funding(super::FundingInfo {
                        txid: [2; 32],
                        vout: 3,
                        value: Value::Explicit(7),
                    }),
                },
            },
            super::TxVaultRow {
                key: super::TxVaultKey {
                    code: b'H',
                    hash: [1; 32],
                    confirmed_height: 2,
                    tx_position: 3,
                    txinfo: super::TxVaultInfo::Funding(super::FundingInfo {
                        txid: [2; 32],
                        vout: 3,
                        value: Value::Null,
                    }),
                },
            },
            super::TxVaultRow {
                key: super::TxVaultKey {
                    code: b'H',
                    hash: [1; 32],
                    confirmed_height: 2,
                    tx_position: 3,
                    txinfo: super::TxVaultInfo::Spending(super::SpendingInfo {
                        txid: [18; 32],
                        vin: 12,
                        prev_txid: "beef".repeat(8).as_bytes().try_into().unwrap(),
                        prev_vout: 9,
                        value: Value::Explicit(14),
                    }),
                },
            },
            super::TxVaultRow {
                key: super::TxVaultKey {
                    code: b'H',
                    hash: [1; 32],
                    confirmed_height: 2,
                    tx_position: 3,
                    txinfo: super::TxVaultInfo::Spending(super::SpendingInfo {
                        txid: [18; 32],
                        vin: 12,
                        prev_txid: "beef".repeat(8).as_bytes().try_into().unwrap(),
                        prev_vout: 9,
                        value: Value::Null,
                    }),
                },
            },
        ];
        for (expected_row, input) in
            IntoIterator::into_iter(expected).zip(IntoIterator::into_iter(inputs))
        {
            let input_row = DBRow {
                key: input,
                value: vec![],
            };
            assert_eq!(TxVaultRow::from_row(input_row).key, expected_row.key);
        }

        #[rustfmt::skip]
        assert_eq!(
            TxVaultRow::prefix_height(b'H', "beef".repeat(8).as_bytes(), 1337),
            vec![
                // code
                72,
                // hash
                98, 101, 101, 102, 98, 101, 101, 102, 98, 101, 101, 102, 98, 101, 101, 102,
                98, 101, 101, 102, 98, 101, 101, 102, 98, 101, 101, 102, 98, 101, 101, 102,
                // height
                0, 0, 5, 57
            ]
        );
    }
}
