#[cfg(not(feature = "liquid"))]
use bitcoin::VarInt;
use bitcoin::{hashes::sha256d::Hash as Sha256dHash, ScriptBuf};
use itertools::Itertools;
use rayon::prelude::*;
use sha2::{Digest, Sha256};

#[cfg(not(feature = "liquid"))]
use bitcoin::consensus::encode::{deserialize, serialize};
#[cfg(feature = "liquid")]
use elements::{
    encode::{deserialize, serialize},
    AssetId,
};

use std::collections::{BTreeSet, HashMap, HashSet};
use std::convert::TryInto;
use std::path::Path;
use std::sync::{Arc, RwLock};

use crate::chain::{BlockHash, BlockHeader, Network, OutPoint, Transaction, TxOut, Txid, Value};
use crate::config::Config;
use crate::daemon::Daemon;
use crate::errors::*;
use crate::metrics::{Gauge, HistogramOpts, HistogramTimer, HistogramVec, MetricOpts, Metrics};
use crate::util::{
    bincode_util, full_hash, has_prevout, is_spendable, BlockHeaderMeta, BlockId, BlockMeta,
    BlockStatus, Bytes, HeaderEntry, HeaderList, ScriptToAddr,
};

use crate::new_index::db::{DBFlush, DBRow, ReverseScanIterator, ScanIterator, DB};
use crate::new_index::fetch::{start_fetcher, BlockEntry, FetchFrom};

#[cfg(feature = "liquid")]
use crate::elements::{asset, peg};

use super::{
    db::ReverseScanGroupIterator,
    vault::{self, VaultStore},
};

type UtxoMap = HashMap<OutPoint, (BlockId, Value)>;

#[derive(Debug)]
pub struct Utxo {
    pub txid: Txid,
    pub vout: u32,
    pub confirmed: Option<BlockId>,
    pub value: Value,

    #[cfg(feature = "liquid")]
    pub asset: elements::confidential::Asset,
    #[cfg(feature = "liquid")]
    pub nonce: elements::confidential::Nonce,
    #[cfg(feature = "liquid")]
    pub witness: elements::TxOutWitness,
}

impl From<&Utxo> for OutPoint {
    fn from(utxo: &Utxo) -> Self {
        OutPoint {
            txid: utxo.txid,
            vout: utxo.vout,
        }
    }
}

#[derive(Debug)]
pub struct SpendingInput {
    pub txid: Txid,
    pub vin: u32,
    pub confirmed: Option<BlockId>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct ScriptStats {
    pub tx_count: usize,
    pub funded_txo_count: usize,
    pub spent_txo_count: usize,
    #[cfg(not(feature = "liquid"))]
    pub funded_txo_sum: u64,
    #[cfg(not(feature = "liquid"))]
    pub spent_txo_sum: u64,
}

impl ScriptStats {
    #[cfg(feature = "liquid")]
    fn is_sane(&self) -> bool {
        // See below for comments.
        self.spent_txo_count <= self.funded_txo_count
            && self.tx_count <= self.spent_txo_count + self.funded_txo_count
    }
    #[cfg(not(feature = "liquid"))]
    fn is_sane(&self) -> bool {
        // There are less or equal spends to funds
        self.spent_txo_count <= self.funded_txo_count
        // There are less or equal transactions to total spent+funded txo counts
        // (Most spread out txo case = N funds in 1 tx each + M spends in 1 tx each = N + M txes)
        && self.tx_count <= self.spent_txo_count + self.funded_txo_count
        // There are less or equal spent coins to funded coins
        && self.spent_txo_sum <= self.funded_txo_sum
        // If funded and spent txos are equal (0 balance)
        // Then funded and spent coins must be equal (0 balance)
        && (self.funded_txo_count == self.spent_txo_count)
            == (self.funded_txo_sum == self.spent_txo_sum)
    }
}

fn load_blockhashes(db: &DB, prefix: &[u8]) -> HashSet<BlockHash> {
    db.iter_scan(prefix)
        .map(BlockRow::from_row)
        .map(|r| deserialize(&r.key.hash).expect("failed to parse BlockHash"))
        .collect()
}

fn load_blockheaders(db: &DB) -> HashMap<BlockHash, BlockHeader> {
    db.iter_scan(&BlockRow::header_filter())
        .map(BlockRow::from_row)
        .map(|r| {
            let key: BlockHash = deserialize(&r.key.hash).expect("failed to parse BlockHash");
            let value: BlockHeader = deserialize(&r.value).expect("failed to parse BlockHeader");
            (key, value)
        })
        .collect()
}

#[derive(Serialize, Deserialize)]
struct TxRowKey {
    code: u8,
    txid: FullHash,
}

struct TxRow {
    key: TxRowKey,
    value: Bytes, // raw transaction
}

impl TxRow {
    fn new(txn: &Transaction) -> TxRow {
        let txid = full_hash(&txn.compute_txid()[..]);
        TxRow {
            key: TxRowKey { code: b'T', txid },
            value: serialize(txn),
        }
    }

    fn key(prefix: &[u8]) -> Bytes {
        [b"T", prefix].concat()
    }

    fn into_row(self) -> DBRow {
        let TxRow { key, value } = self;
        DBRow {
            key: bincode_util::serialize_little(&key).unwrap(),
            value,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct TxConfKey {
    code: u8,
    txid: FullHash,
    blockhash: FullHash,
}

struct TxConfRow {
    key: TxConfKey,
}

impl TxConfRow {
    fn new(txn: &Transaction, blockhash: FullHash) -> TxConfRow {
        let txid = full_hash(&txn.compute_txid()[..]);
        TxConfRow {
            key: TxConfKey {
                code: b'C',
                txid,
                blockhash,
            },
        }
    }

    fn filter(prefix: &[u8]) -> Bytes {
        [b"C", prefix].concat()
    }

    fn into_row(self) -> DBRow {
        DBRow {
            key: bincode_util::serialize_little(&self.key).unwrap(),
            value: vec![],
        }
    }

    fn from_row(row: DBRow) -> Self {
        TxConfRow {
            key: bincode_util::deserialize_little(&row.key).expect("failed to parse TxConfKey"),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct TxOutKey {
    code: u8,
    txid: FullHash,
    vout: u32,
}

struct TxOutRow {
    key: TxOutKey,
    value: Bytes, // serialized output
}

impl TxOutRow {
    fn new(txid: &FullHash, vout: usize, txout: &TxOut) -> TxOutRow {
        TxOutRow {
            key: TxOutKey {
                code: b'O',
                txid: *txid,
                vout: vout as u32,
            },
            value: serialize(txout),
        }
    }
    fn key(outpoint: &OutPoint) -> Bytes {
        bincode_util::serialize_little(&TxOutKey {
            code: b'O',
            txid: full_hash(&outpoint.txid[..]),
            vout: outpoint.vout,
        })
        .unwrap()
    }

    fn into_row(self) -> DBRow {
        DBRow {
            key: bincode_util::serialize_little(&self.key).unwrap(),
            value: self.value,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct BlockKey {
    code: u8,
    hash: FullHash,
}

pub struct BlockRow {
    key: BlockKey,
    value: Bytes, // serialized output
}

impl BlockRow {
    fn new_header(block_entry: &BlockEntry) -> BlockRow {
        BlockRow {
            key: BlockKey {
                code: b'B',
                hash: full_hash(&block_entry.entry.hash()[..]),
            },
            value: serialize(&block_entry.block.header),
        }
    }

    fn new_txids(hash: FullHash, txids: &[Txid]) -> BlockRow {
        BlockRow {
            key: BlockKey { code: b'X', hash },
            value: bincode_util::serialize_little(txids).unwrap(),
        }
    }

    fn new_meta(hash: FullHash, meta: &BlockMeta) -> BlockRow {
        BlockRow {
            key: BlockKey { code: b'M', hash },
            value: bincode_util::serialize_little(meta).unwrap(),
        }
    }

    fn new_done(hash: FullHash) -> BlockRow {
        BlockRow {
            key: BlockKey { code: b'D', hash },
            value: vec![],
        }
    }

    fn header_filter() -> Bytes {
        b"B".to_vec()
    }

    pub fn txids_key(hash: FullHash) -> Bytes {
        [b"X", &hash[..]].concat()
    }

    pub fn meta_key(hash: FullHash) -> Bytes {
        [b"M", &hash[..]].concat()
    }

    pub fn done_filter() -> Bytes {
        b"D".to_vec()
    }

    pub fn into_row(self) -> DBRow {
        DBRow {
            key: bincode_util::serialize_little(&self.key).unwrap(),
            value: self.value,
        }
    }

    pub fn from_row(row: DBRow) -> Self {
        BlockRow {
            key: bincode_util::deserialize_little(&row.key).unwrap(),
            value: row.value,
        }
    }
}

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
pub enum TxHistoryInfo {
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

impl TxHistoryInfo {
    pub fn get_txid(&self) -> Txid {
        match self {
            TxHistoryInfo::Funding(FundingInfo { txid, .. })
            | TxHistoryInfo::Spending(SpendingInfo { txid, .. }) => deserialize(txid),

            #[cfg(feature = "liquid")]
            TxHistoryInfo::Issuing(asset::IssuingInfo { txid, .. })
            | TxHistoryInfo::Burning(asset::BurningInfo { txid, .. })
            | TxHistoryInfo::Pegin(peg::PeginInfo { txid, .. })
            | TxHistoryInfo::Pegout(peg::PegoutInfo { txid, .. }) => deserialize(txid),
        }
        .expect("cannot parse Txid")
    }
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct TxHistoryKey {
    pub code: u8,              // H for script history or I for asset history (elements only)
    pub hash: FullHash, // either a scripthash (always on bitcoin) or an asset id (elements only)
    pub confirmed_height: u32, // MUST be serialized as big-endian (for correct scans).
    pub tx_position: u16, // MUST be serialized as big-endian (for correct scans). Position in block.
    pub txinfo: TxHistoryInfo,
}

pub struct TxHistoryRow {
    pub key: TxHistoryKey,
}

impl TxHistoryRow {
    fn new(
        script: &ScriptBuf,
        confirmed_height: u32,
        tx_position: u16,
        txinfo: TxHistoryInfo,
    ) -> Self {
        let key = TxHistoryKey {
            code: b'H',
            hash: compute_script_hash(script),
            confirmed_height,
            tx_position,
            txinfo,
        };
        TxHistoryRow { key }
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
            bincode_util::deserialize_big(&row.key).expect("failed to deserialize TxHistoryKey");
        TxHistoryRow { key }
    }

    pub fn get_txid(&self) -> Txid {
        self.key.txinfo.get_txid()
    }
    fn get_funded_outpoint(&self) -> OutPoint {
        self.key.txinfo.get_funded_outpoint()
    }
}

impl TxHistoryInfo {
    // for funding rows, returns the funded output.
    // for spending rows, returns the spent previous output.
    pub fn get_funded_outpoint(&self) -> OutPoint {
        match self {
            TxHistoryInfo::Funding(ref info) => OutPoint {
                txid: deserialize(&info.txid).unwrap(),
                vout: info.vout,
            },
            TxHistoryInfo::Spending(ref info) => OutPoint {
                txid: deserialize(&info.prev_txid).unwrap(),
                vout: info.prev_vout,
            },
            #[cfg(feature = "liquid")]
            TxHistoryInfo::Issuing(_)
            | TxHistoryInfo::Burning(_)
            | TxHistoryInfo::Pegin(_)
            | TxHistoryInfo::Pegout(_) => unreachable!(),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct TxHistorySummary {
    txid: Txid,
    height: usize,
    value: i64,
    time: u32,
    tx_position: u16,
}

#[derive(Serialize, Deserialize)]
struct TxEdgeKey {
    code: u8,
    funding_txid: FullHash,
    funding_vout: u32,
    spending_txid: FullHash,
    spending_vin: u32,
}

struct TxEdgeRow {
    key: TxEdgeKey,
}

impl TxEdgeRow {
    fn new(
        funding_txid: FullHash,
        funding_vout: u32,
        spending_txid: FullHash,
        spending_vin: u32,
    ) -> Self {
        let key = TxEdgeKey {
            code: b'S',
            funding_txid,
            funding_vout,
            spending_txid,
            spending_vin,
        };
        TxEdgeRow { key }
    }

    fn filter(outpoint: &OutPoint) -> Bytes {
        // TODO build key without using bincode? [ b"S", &outpoint.txid[..], outpoint.vout?? ].concat()
        bincode_util::serialize_little(&(b'S', full_hash(&outpoint.txid[..]), outpoint.vout))
            .unwrap()
    }

    fn into_row(self) -> DBRow {
        DBRow {
            key: bincode_util::serialize_little(&self.key).unwrap(),
            value: vec![],
        }
    }

    fn from_row(row: DBRow) -> Self {
        TxEdgeRow {
            key: bincode_util::deserialize_little(&row.key)
                .expect("failed to deserialize TxEdgeKey"),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct ScriptCacheKey {
    code: u8,
    scripthash: FullHash,
}

struct StatsCacheRow {
    key: ScriptCacheKey,
    value: Bytes,
}

impl StatsCacheRow {
    fn new(scripthash: &[u8], stats: &ScriptStats, blockhash: &BlockHash) -> Self {
        StatsCacheRow {
            key: ScriptCacheKey {
                code: b'A',
                scripthash: full_hash(scripthash),
            },
            value: bincode_util::serialize_little(&(stats, blockhash)).unwrap(),
        }
    }

    pub fn key(scripthash: &[u8]) -> Bytes {
        [b"A", scripthash].concat()
    }

    fn into_row(self) -> DBRow {
        DBRow {
            key: bincode_util::serialize_little(&self.key).unwrap(),
            value: self.value,
        }
    }
}

type CachedUtxoMap = HashMap<(Txid, u32), (u32, Value)>; // (txid,vout) => (block_height,output_value)

struct UtxoCacheRow {
    key: ScriptCacheKey,
    value: Bytes,
}

impl UtxoCacheRow {
    fn new(scripthash: &[u8], utxos: &UtxoMap, blockhash: &BlockHash) -> Self {
        let utxos_cache = make_utxo_cache(utxos);

        UtxoCacheRow {
            key: ScriptCacheKey {
                code: b'U',
                scripthash: full_hash(scripthash),
            },
            value: bincode_util::serialize_little(&(utxos_cache, blockhash)).unwrap(),
        }
    }

    pub fn key(scripthash: &[u8]) -> Bytes {
        [b"U", scripthash].concat()
    }

    fn into_row(self) -> DBRow {
        DBRow {
            key: bincode_util::serialize_little(&self.key).unwrap(),
            value: self.value,
        }
    }
}

// keep utxo cache with just the block height (the hash/timestamp are read later from the headers to reconstruct BlockId)
// and use a (txid,vout) tuple instead of OutPoints (they don't play nicely with bincode serialization)
fn make_utxo_cache(utxos: &UtxoMap) -> CachedUtxoMap {
    utxos
        .iter()
        .map(|(outpoint, (blockid, value))| {
            (
                (outpoint.txid, outpoint.vout),
                (blockid.height as u32, *value),
            )
        })
        .collect()
}

fn from_utxo_cache(utxos_cache: CachedUtxoMap, chain: &ChainQuery) -> UtxoMap {
    utxos_cache
        .into_iter()
        .map(|((txid, vout), (height, value))| {
            let outpoint = OutPoint { txid, vout };
            let blockid = chain
                .blockid_by_height(height as usize)
                .expect("missing blockheader for valid utxo cache entry");
            (outpoint, (blockid, value))
        })
        .collect()
}

// TODO: replace by a separate opaque type (similar to Sha256dHash, but without the "double")
pub type FullHash = [u8; 32]; // serialized SHA256 result

pub fn compute_script_hash(script: &ScriptBuf) -> FullHash {
    let mut hasher = Sha256::new();
    hasher.update(script.as_bytes());
    hasher.finalize()[..]
        .try_into()
        .expect("SHA256 size is 32 bytes")
}

pub fn parse_hash(hash: &FullHash) -> Sha256dHash {
    deserialize(hash).expect("failed to parse Sha256dHash")
}

#[cfg(all(test, feature = "liquid"))]
mod tests {
    use super::{DBRow, TxHistoryRow};
    use crate::chain::Value;
    use std::convert::TryInto;

    #[test]
    fn tx_history_row_ser_deser_tests() {
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
                // TxHistoryInfo variant (Funding)
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
            super::TxHistoryRow {
                key: super::TxHistoryKey {
                    code: b'H',
                    hash: [1; 32],
                    confirmed_height: 2,
                    tx_position: 3,
                    txinfo: super::TxHistoryInfo::Funding(super::FundingInfo {
                        txid: [2; 32],
                        vout: 3,
                        value: Value::Explicit(7),
                    }),
                },
            },
            super::TxHistoryRow {
                key: super::TxHistoryKey {
                    code: b'H',
                    hash: [1; 32],
                    confirmed_height: 2,
                    tx_position: 3,
                    txinfo: super::TxHistoryInfo::Funding(super::FundingInfo {
                        txid: [2; 32],
                        vout: 3,
                        value: Value::Null,
                    }),
                },
            },
            super::TxHistoryRow {
                key: super::TxHistoryKey {
                    code: b'H',
                    hash: [1; 32],
                    confirmed_height: 2,
                    tx_position: 3,
                    txinfo: super::TxHistoryInfo::Spending(super::SpendingInfo {
                        txid: [18; 32],
                        vin: 12,
                        prev_txid: "beef".repeat(8).as_bytes().try_into().unwrap(),
                        prev_vout: 9,
                        value: Value::Explicit(14),
                    }),
                },
            },
            super::TxHistoryRow {
                key: super::TxHistoryKey {
                    code: b'H',
                    hash: [1; 32],
                    confirmed_height: 2,
                    tx_position: 3,
                    txinfo: super::TxHistoryInfo::Spending(super::SpendingInfo {
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
            assert_eq!(TxHistoryRow::from_row(input_row).key, expected_row.key);
        }

        #[rustfmt::skip]
        assert_eq!(
            TxHistoryRow::prefix_height(b'H', "beef".repeat(8).as_bytes(), 1337),
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
