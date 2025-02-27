use std::collections::HashMap;
use std::convert::TryInto;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
#[cfg(feature = "electrum-discovery")]
use std::net::IpAddr;
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;

use bitcoin::hashes::sha256d::Hash as Sha256dHash;
use error_chain::ChainedError;
use hex;
use hex::ToHex as _;
use serde_json::{from_str, Value};
use sha2::{Digest, Sha256};

#[cfg(not(feature = "liquid"))]
use bitcoin::consensus::encode::serialize;
#[cfg(feature = "liquid")]
use elements::encode::serialize;

use crate::chain::Txid;
use crate::config::{Config, VERSION_STRING};
use crate::electrum::{get_electrum_height, ProtocolVersion};
use crate::errors::*;
use crate::metrics::{Gauge, HistogramOpts, HistogramVec, MetricOpts, Metrics};
use crate::new_index::vault::TxVaultRow;
use crate::new_index::{Query, Utxo};
use crate::util::electrum_merkle::{get_header_merkle_proof, get_id_from_pos, get_tx_merkle_proof};
use crate::util::{
    create_socket, full_hash, spawn_thread, BlockId, BoolThen, Channel, FullHash, HeaderEntry,
    SyncChannel,
};

const PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::new(1, 4);
const MAX_HEADERS: usize = 2016;

#[cfg(feature = "electrum-discovery")]
use crate::electrum::{DiscoveryManager, ServerFeatures};

use super::vault::VaultServer;

// TODO: Sha256dHash should be a generic hash-container (since script hash is single SHA256)
fn hash_from_value(val: Option<&Value>) -> Result<Sha256dHash> {
    let script_hash = val.chain_err(|| "missing hash")?;
    let script_hash = script_hash.as_str().chain_err(|| "non-string hash")?;
    let script_hash = script_hash.parse().chain_err(|| "non-hex hash")?;
    Ok(script_hash)
}

fn usize_from_value(val: Option<&Value>, name: &str) -> Result<usize> {
    let val = val.chain_err(|| format!("missing {}", name))?;
    let val = val.as_u64().chain_err(|| format!("non-integer {}", name))?;
    Ok(val as usize)
}

fn usize_from_value_or(val: Option<&Value>, name: &str, default: usize) -> Result<usize> {
    if val.is_none() {
        return Ok(default);
    }
    usize_from_value(val, name)
}

fn bool_from_value(val: Option<&Value>, name: &str) -> Result<bool> {
    let val = val.chain_err(|| format!("missing {}", name))?;
    let val = val.as_bool().chain_err(|| format!("not a bool {}", name))?;
    Ok(val)
}

fn bool_from_value_or(val: Option<&Value>, name: &str, default: bool) -> Result<bool> {
    if val.is_none() {
        return Ok(default);
    }
    bool_from_value(val, name)
}

// TODO: implement caching and delta updates
fn get_status_hash(txs: Vec<(Txid, Option<BlockId>)>, query: &Query) -> Option<FullHash> {
    if txs.is_empty() {
        None
    } else {
        let mut hasher = Sha256::new();
        for (txid, blockid) in txs {
            let is_mempool = blockid.is_none();
            let has_unconfirmed_parents = is_mempool
                .and_then(|| Some(query.has_unconfirmed_parents(&txid)))
                .unwrap_or(false);
            let height = get_electrum_height(blockid, has_unconfirmed_parents);
            let part = format!("{}:{}:", txid, height);
            hasher.update(part.as_bytes());
        }
        Some(
            hasher.finalize()[..]
                .try_into()
                .expect("SHA256 size is 32 bytes"),
        )
    }
}

struct Connection {
    query: Arc<Query>,
    last_header_entry: Option<HeaderEntry>,
    //Store last vault key for subscription
    last_vault_entry: Option<TxVaultRow>,
    last_vault_batch_size: usize,
    status_hashes: HashMap<Sha256dHash, Value>, // ScriptHash -> StatusHash
    stream: ConnectionStream,
    chan: SyncChannel<Message>,
    stats: Arc<Stats>,
    txs_limit: usize,
    die_please: Option<Receiver<()>>,
    // Vault
    vault: VaultServer,
    #[cfg(feature = "electrum-discovery")]
    discovery: Option<Arc<DiscoveryManager>>,
}

impl Connection {
    pub fn new(
        query: Arc<Query>,
        stream: ConnectionStream,
        stats: Arc<Stats>,
        txs_limit: usize,
        die_please: Receiver<()>,
        #[cfg(feature = "electrum-discovery")] discovery: Option<Arc<DiscoveryManager>>,
    ) -> Connection {
        let vault = VaultServer::new(query.clone());
        Connection {
            query,
            last_header_entry: None, // disable header subscription for now
            last_vault_entry: None,  // disable vault subscription for now
            last_vault_batch_size: 1,
            status_hashes: HashMap::new(),
            stream,
            chan: SyncChannel::new(10),
            stats,
            txs_limit,
            die_please: Some(die_please),
            vault,
            #[cfg(feature = "electrum-discovery")]
            discovery,
        }
    }

    fn blockchain_headers_subscribe(&mut self) -> Result<Value> {
        let entry = self.query.chain().best_header();
        let hex_header = hex::encode(serialize(entry.header()));
        let result = json!({"hex": hex_header, "height": entry.height()});
        self.last_header_entry = Some(entry);
        Ok(result)
    }

    fn server_version(&self) -> Result<Value> {
        Ok(json!([VERSION_STRING.as_str(), PROTOCOL_VERSION]))
    }

    fn server_banner(&self) -> Result<Value> {
        Ok(json!(self.query.config().electrum_banner.clone()))
    }

    #[cfg(feature = "electrum-discovery")]
    fn server_features(&self) -> Result<Value> {
        let discovery = self
            .discovery
            .as_ref()
            .chain_err(|| "discovery is disabled")?;
        Ok(json!(discovery.our_features()))
    }

    fn server_donation_address(&self) -> Result<Value> {
        Ok(Value::Null)
    }

    fn server_peers_subscribe(&self) -> Result<Value> {
        #[cfg(feature = "electrum-discovery")]
        let servers = self
            .discovery
            .as_ref()
            .map_or_else(|| json!([]), |d| json!(d.get_servers()));

        #[cfg(not(feature = "electrum-discovery"))]
        let servers = json!([]);

        Ok(servers)
    }

    #[cfg(feature = "electrum-discovery")]
    fn server_add_peer(&self, params: &[Value]) -> Result<Value> {
        let ip = self
            .stream
            .ip()
            .ok_or(Error::from("Can't add peer with Unix sockets enabled"))?;
        let discovery = self
            .discovery
            .as_ref()
            .chain_err(|| "discovery is disabled")?;

        let features = params
            .first()
            .chain_err(|| "missing features param")?
            .clone();
        let features = serde_json::from_value(features).chain_err(|| "invalid features")?;

        discovery.add_server_request(ip, features)?;
        Ok(json!(true))
    }

    fn mempool_get_fee_histogram(&self) -> Result<Value> {
        Ok(json!(&self.query.mempool().backlog_stats().fee_histogram))
    }

    fn blockchain_block_header(&self, params: &[Value]) -> Result<Value> {
        let height = usize_from_value(params.first(), "height")?;
        let cp_height = usize_from_value_or(params.get(1), "cp_height", 0)?;

        let raw_header_hex: String = self
            .query
            .chain()
            .header_by_height(height)
            .map(|entry| entry.hash().encode_hex())
            //.map(|entry| hex::encode(serialize(entry.header())))
            .chain_err(|| "missing header")?;

        if cp_height == 0 {
            return Ok(json!(raw_header_hex));
        }
        let (branch, root) = get_header_merkle_proof(self.query.chain(), height, cp_height)?;

        Ok(json!({
            "header": raw_header_hex,
            "root": root,
            "branch": branch
        }))
    }

    fn blockchain_block_headers(&self, params: &[Value]) -> Result<Value> {
        let start_height = usize_from_value(params.first(), "start_height")?;
        let count = MAX_HEADERS.min(usize_from_value(params.get(1), "count")?);
        let cp_height = usize_from_value_or(params.get(2), "cp_height", 0)?;
        let heights: Vec<usize> = (start_height..(start_height + count)).collect();
        let headers: Vec<String> = heights
            .into_iter()
            .filter_map(|height| {
                self.query
                    .chain()
                    .header_by_height(height)
                    .map(|entry| entry.hash().encode_hex())
                //.map(|entry| hex::encode(serialize(entry.header())))
            })
            .collect();

        if count == 0 || cp_height == 0 {
            return Ok(json!({
                "count": headers.len(),
                "hex": headers.join(""),
                "max": MAX_HEADERS,
            }));
        }

        let (branch, root) =
            get_header_merkle_proof(self.query.chain(), start_height + (count - 1), cp_height)?;

        Ok(json!({
            "count": headers.len(),
            "hex": headers.join(""),
            "max": MAX_HEADERS,
            "root": root,
            "branch" : branch,
        }))
    }

    fn blockchain_estimatefee(&self, params: &[Value]) -> Result<Value> {
        let conf_target = usize_from_value(params.first(), "blocks_count")?;
        let fee_rate = self
            .query
            .estimate_fee(conf_target as u16)
            .chain_err(|| format!("cannot estimate fee for {} blocks", conf_target))?;
        // convert from sat/b to BTC/kB, as expected by Electrum clients
        Ok(json!(fee_rate / 100_000f64))
    }

    fn blockchain_relayfee(&self) -> Result<Value> {
        let relayfee = self.query.get_relayfee()?;
        // convert from sat/b to BTC/kB, as expected by Electrum clients
        Ok(json!(relayfee / 100_000f64))
    }

    fn blockchain_scripthash_subscribe(&mut self, params: &[Value]) -> Result<Value> {
        let script_hash = hash_from_value(params.first()).chain_err(|| "bad script_hash")?;

        let history_txids = get_history(&self.query, &script_hash[..], self.txs_limit)?;
        let status_hash = get_status_hash(history_txids, &self.query)
            .map_or(Value::Null, |h| json!(hex::encode(full_hash(&h[..]))));

        if self
            .status_hashes
            .insert(script_hash, status_hash.clone())
            .is_none()
        {
            self.stats.subscriptions.inc();
        }
        Ok(status_hash)
    }

    #[cfg(not(feature = "liquid"))]
    fn blockchain_scripthash_get_balance(&self, params: &[Value]) -> Result<Value> {
        let script_hash = hash_from_value(params.first()).chain_err(|| "bad script_hash")?;
        let (chain_stats, mempool_stats) = self.query.stats(&script_hash[..]);

        Ok(json!({
            "confirmed": chain_stats.funded_txo_sum - chain_stats.spent_txo_sum,
            "unconfirmed": mempool_stats.funded_txo_sum as i64 - mempool_stats.spent_txo_sum as i64,
        }))
    }

    fn blockchain_scripthash_get_history(&self, params: &[Value]) -> Result<Value> {
        let script_hash = hash_from_value(params.first()).chain_err(|| "bad script_hash")?;
        let history_txids = get_history(&self.query, &script_hash[..], self.txs_limit)?;

        Ok(json!(history_txids
            .into_iter()
            .map(|(txid, blockid)| {
                let is_mempool = blockid.is_none();
                let fee = is_mempool.and_then(|| self.query.get_mempool_tx_fee(&txid));
                let has_unconfirmed_parents = is_mempool
                    .and_then(|| Some(self.query.has_unconfirmed_parents(&txid)))
                    .unwrap_or(false);
                let height = get_electrum_height(blockid, has_unconfirmed_parents);
                GetHistoryResult { txid, height, fee }
            })
            .collect::<Vec<_>>()))
    }

    fn blockchain_scripthash_listunspent(&self, params: &[Value]) -> Result<Value> {
        let script_hash = hash_from_value(params.first()).chain_err(|| "bad script_hash")?;
        let utxos = self.query.utxo(&script_hash[..])?;

        let to_json = |utxo: Utxo| {
            let json = json!({
                "height": utxo.confirmed.map_or(0, |b| b.height),
                "tx_pos": utxo.vout,
                "tx_hash": utxo.txid,
                "value": utxo.value,
            });

            #[cfg(feature = "liquid")]
            let json = {
                let mut json = json;
                json["asset"] = json!(utxo.asset);
                json["nonce"] = json!(utxo.nonce);
                json
            };

            json
        };

        Ok(json!(Value::Array(
            utxos.into_iter().map(to_json).collect()
        )))
    }

    fn blockchain_transaction_broadcast(&self, params: &[Value]) -> Result<Value> {
        let tx = params.first().chain_err(|| "missing tx")?;
        let tx = tx.as_str().chain_err(|| "non-string tx")?.to_string();
        let txid = self.query.broadcast_raw(&tx)?;
        if let Err(e) = self.chan.sender().try_send(Message::PeriodicUpdate) {
            warn!("failed to issue PeriodicUpdate after broadcast: {}", e);
        }
        Ok(json!(txid))
    }

    fn blockchain_transaction_get(&self, params: &[Value]) -> Result<Value> {
        let tx_hash = Txid::from(hash_from_value(params.first()).chain_err(|| "bad tx_hash")?);
        let verbose = match params.get(1) {
            Some(value) => value.as_bool().chain_err(|| "non-bool verbose value")?,
            None => false,
        };

        // FIXME: implement verbose support
        if verbose {
            bail!("verbose transactions are currently unsupported");
        }

        let tx = self
            .query
            .lookup_raw_txn(&tx_hash)
            .chain_err(|| "missing transaction")?;
        Ok(json!(hex::encode(tx)))
    }

    fn blockchain_transaction_get_merkle(&self, params: &[Value]) -> Result<Value> {
        let txid = Txid::from(hash_from_value(params.first()).chain_err(|| "bad tx_hash")?);
        let height = usize_from_value(params.get(1), "height")?;
        let blockid = self
            .query
            .chain()
            .tx_confirming_block(&txid)
            .ok_or("tx not found or is unconfirmed")?;
        if blockid.height != height {
            bail!("invalid confirmation height provided");
        }
        let (merkle, pos) = get_tx_merkle_proof(self.query.chain(), &txid, &blockid.hash)
            .chain_err(|| "cannot create merkle proof")?;
        Ok(json!({
                "block_height": blockid.height,
                "merkle": merkle,
                "pos": pos}))
    }

    fn blockchain_transaction_id_from_pos(&self, params: &[Value]) -> Result<Value> {
        let height = usize_from_value(params.first(), "height")?;
        let tx_pos = usize_from_value(params.get(1), "tx_pos")?;
        let want_merkle = bool_from_value_or(params.get(2), "merkle", false)?;

        let (txid, merkle) = get_id_from_pos(self.query.chain(), height, tx_pos, want_merkle)?;

        if !want_merkle {
            return Ok(json!(txid));
        }

        Ok(json!({
            "tx_hash": txid,
            "merkle" : merkle}))
    }
    fn find_vault_transactions(&mut self, params: &[Value]) -> Result<(usize, Vec<TxVaultRow>)> {
        let batch_size = params.first().and_then(|value| value.as_u64()).unwrap_or(1) as usize;
        let hash = params.get(1).and_then(|value| value.as_str());
        trace!(
            "Handle find_vault_transactions request with params {:?}: hash {:?}",
            &params,
            &hash
        );
        let transactions = self.vault.get_transactions_from_hash(batch_size, hash)?;
        Ok((batch_size, transactions))
    }
    fn vault_transactions_get(&mut self, params: &[Value]) -> Result<Value> {
        //Get latest vault transaction form storage
        let (_, transactions) = self.find_vault_transactions(params)?;
        let result = Value::Array(transactions.iter().map(|v| Value::from(v)).collect());
        Ok(result)
    }
    fn vault_transactions_subscribe(&mut self, params: &[Value]) -> Result<Value> {
        let (batch_size, transactions) = self.find_vault_transactions(params)?;
        let result = Value::Array(transactions.iter().map(|v| Value::from(v)).collect());
        //Set value for periodic update
        self.last_vault_batch_size = batch_size;
        if transactions.is_empty() {
            // Get the last vault entry from storage
            self.last_vault_entry = self.vault.get_last_vault().ok().map(|v| v.into());
        } else {
            self.last_vault_entry = transactions.into_iter().last();
        }
        Ok(result)
    }
    fn handle_command(&mut self, method: &str, params: &[Value], id: &Value) -> Result<Value> {
        trace!("Handle command {:?} with params {:?}", &method, &params);
        let timer = self
            .stats
            .latency
            .with_label_values(&[method])
            .start_timer();
        let result = match method {
            "blockchain.block.header" => self.blockchain_block_header(params),
            "blockchain.block.headers" => self.blockchain_block_headers(params),
            "blockchain.estimatefee" => self.blockchain_estimatefee(params),
            "blockchain.headers.subscribe" => self.blockchain_headers_subscribe(),
            "blockchain.relayfee" => self.blockchain_relayfee(),
            #[cfg(not(feature = "liquid"))]
            "blockchain.scripthash.get_balance" => self.blockchain_scripthash_get_balance(params),
            "blockchain.scripthash.get_history" => self.blockchain_scripthash_get_history(params),
            "blockchain.scripthash.listunspent" => self.blockchain_scripthash_listunspent(params),
            "blockchain.scripthash.subscribe" => self.blockchain_scripthash_subscribe(params),
            "blockchain.transaction.broadcast" => self.blockchain_transaction_broadcast(params),
            "blockchain.transaction.get" => self.blockchain_transaction_get(params),
            "blockchain.transaction.get_merkle" => self.blockchain_transaction_get_merkle(params),
            "blockchain.transaction.id_from_pos" => self.blockchain_transaction_id_from_pos(params),
            "mempool.get_fee_histogram" => self.mempool_get_fee_histogram(),
            "server.banner" => self.server_banner(),
            "server.donation_address" => self.server_donation_address(),
            "server.peers.subscribe" => self.server_peers_subscribe(),
            "server.ping" => Ok(Value::Null),
            "server.version" => self.server_version(),

            #[cfg(feature = "electrum-discovery")]
            "server.features" => self.server_features(),
            #[cfg(feature = "electrum-discovery")]
            "server.add_peer" => self.server_add_peer(params),
            // For vault transactions
            "vault.transactions.subscribe" => self.vault_transactions_subscribe(params),
            "vault.transactions.get" => self.vault_transactions_get(params),
            &_ => bail!("unknown method {} {:?}", method, params),
        };
        timer.observe_duration();
        // TODO: return application errors should be sent to the client
        Ok(match result {
            Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
            Err(e) => {
                warn!(
                    "rpc #{} {} {:?} failed: {}",
                    id,
                    method,
                    params,
                    e.display_chain()
                );
                json!({"jsonrpc": "2.0", "id": id, "error": format!("{}", e)})
            }
        })
    }

    fn update_subscriptions(&mut self) -> Result<Vec<Value>> {
        let timer = self
            .stats
            .latency
            .with_label_values(&["periodic_update"])
            .start_timer();
        let mut result = vec![];
        if let Some(ref mut last_entry) = self.last_header_entry {
            let entry = self.query.chain().best_header();
            if *last_entry != entry {
                *last_entry = entry;
                let hex_header = hex::encode(serialize(last_entry.header()));
                let header = json!({"hex": hex_header, "height": last_entry.height()});
                result.push(json!({
                    "jsonrpc": "2.0",
                    "method": "blockchain.headers.subscribe",
                    "params": [header]}));
            }
        }
        //Scalar: Add vault subscription
        let last_key = self.last_vault_entry.as_ref().map(|row| row.key.as_hex());
        let last_key_str = last_key.as_ref().map(|v| v.as_str());
        let vault_txs = self
            .vault
            .get_transactions_from_hash(self.last_vault_batch_size, last_key_str)
            .unwrap_or_default();
        if !vault_txs.is_empty() {
            let vault_txs_len = vault_txs.len();
            let vault_txs_result = Value::Array(vault_txs.iter().map(|v| Value::from(v)).collect());
            self.last_vault_entry = vault_txs.into_iter().last();
            let vault_tx = self.last_vault_entry.as_ref().unwrap();
            debug!(
                "Found {} vault txs. Latest vault tx at {:?}:{:?} {:?} with key {:?}",
                vault_txs_len,
                &vault_tx.key.height,
                &vault_tx.key.position,
                &vault_tx.info.txid,
                &vault_tx.key.as_hex()
            );
            result.push(json!({
                        "jsonrpc": "2.0",
                        "method": "vault.transactions.subscribe",
                        "params": vault_txs_result}));
        } else {
            debug!("Latest vault transaction not found");
        }

        for (script_hash, status_hash) in self.status_hashes.iter_mut() {
            let history_txids = get_history(&self.query, &script_hash[..], self.txs_limit)?;
            let new_status_hash = get_status_hash(history_txids, &self.query)
                .map_or(Value::Null, |h| json!(hex::encode(full_hash(&h[..]))));
            if new_status_hash == *status_hash {
                continue;
            }
            result.push(json!({
                "jsonrpc": "2.0",
                "method": "blockchain.scripthash.subscribe",
                "params": [script_hash, new_status_hash]}));
            *status_hash = new_status_hash;
        }
        timer.observe_duration();
        Ok(result)
    }

    fn send_values(&mut self, values: &[Value]) -> Result<()> {
        for value in values {
            let line = value.to_string() + "\n";
            self.stream
                .write_all(line.as_bytes())
                .chain_err(|| format!("failed to send {}", value))?;
        }
        Ok(())
    }

    fn handle_replies(&mut self, shutdown: crossbeam_channel::Receiver<()>) -> Result<()> {
        loop {
            crossbeam_channel::select! {
                recv(self.chan.receiver()) -> msg => {
                    let msg = msg.chain_err(|| "channel closed")?;
                    trace!("RPC {:?}", msg);
                    match msg {
                        Message::Request(line) => {
                            let result = self.handle_line(&line);
                            // trace!("Handle Request {:?} with result {:?}", &line, &result);
                            self.send_values(&[result])?
                        }
                        Message::PeriodicUpdate => {
                            let values = self
                                .update_subscriptions()
                                .chain_err(|| "failed to update subscriptions")?;
                            if !values.is_empty() {
                                trace!("Handle PeriodicUpdate with values {:?}", &values);
                            }
                            self.send_values(&values)?
                        }
                        Message::Done => {
                            self.chan.close();
                            return Ok(());
                        }
                    }
                }
                recv(shutdown) -> _ => {
                    self.chan.close();
                    return Ok(());
                }
            }
        }
    }

    #[inline]
    fn handle_line(&mut self, line: &String) -> Value {
        if let Ok(json_value) = from_str(line) {
            match json_value {
                Value::Array(mut arr) => {
                    for cmd in &mut arr {
                        // Replace each cmd with its response in-memory.
                        *cmd = self.handle_value(cmd);
                    }
                    Value::Array(arr)
                }
                cmd => self.handle_value(&cmd),
            }
        } else {
            // serde_json was unable to parse
            invalid_json_rpc(line)
        }
    }

    #[inline]
    fn handle_value(&mut self, value: &Value) -> Value {
        match (
            value.get("method"),
            value.get("params").unwrap_or(&json!([])),
            value.get("id"),
        ) {
            (Some(Value::String(method)), Value::Array(params), Some(id)) => self
                .handle_command(method, params, id)
                .unwrap_or_else(|err| {
                    json!({
                        "error": {
                            "code": 1,
                            "message": format!("{method} RPC error: {err}")
                        },
                        "id": id,
                        "jsonrpc": "2.0"
                    })
                }),
            _ => invalid_json_rpc(value),
        }
    }

    fn handle_requests(
        mut reader: BufReader<ConnectionStream>,
        tx: crossbeam_channel::Sender<Message>,
    ) -> Result<()> {
        loop {
            let mut line = Vec::<u8>::new();
            reader
                .read_until(b'\n', &mut line)
                .chain_err(|| "failed to read a request")?;
            if line.is_empty() {
                tx.send(Message::Done).chain_err(|| "channel closed")?;
                return Ok(());
            } else {
                if line.starts_with(&[22, 3, 1]) {
                    // (very) naive SSL handshake detection
                    let _ = tx.send(Message::Done);
                    bail!("invalid request - maybe SSL-encrypted data?: {:?}", line)
                }
                match String::from_utf8(line) {
                    Ok(req) => tx
                        .send(Message::Request(req))
                        .chain_err(|| "channel closed")?,
                    Err(err) => {
                        let _ = tx.send(Message::Done);
                        bail!("invalid UTF8: {}", err)
                    }
                }
            }
        }
    }

    pub fn run(mut self) {
        self.stats.clients.inc();
        let reader = BufReader::new(self.stream.try_clone().expect("failed to clone TcpStream"));
        let tx = self.chan.sender();

        let die_please = self.die_please.take().unwrap();
        let (reply_killer, reply_receiver) = crossbeam_channel::unbounded();

        // We create a clone of the stream and put it in an Arc
        // This will drop at the end of the function.
        let arc_stream = Arc::new(self.stream.try_clone().expect("failed to clone TcpStream"));
        // We don't want to keep the stream alive until SIGINT
        // It should drop (close) no matter what.
        let maybe_stream = Arc::downgrade(&arc_stream);
        spawn_thread("properly-die", move || {
            let _ = die_please.recv();
            let _ = maybe_stream.upgrade().map(|s| s.shutdown(Shutdown::Both));
            let _ = reply_killer.send(());
        });

        let child = spawn_thread("reader", || Connection::handle_requests(reader, tx));
        if let Err(e) = self.handle_replies(reply_receiver) {
            error!(
                "[{}] connection handling failed: {}",
                self.stream.addr_string(),
                e.display_chain().to_string()
            );
        }
        self.stats.clients.dec();
        self.stats
            .subscriptions
            .sub(self.status_hashes.len() as i64);

        let addr = self.stream.addr_string();
        debug!("[{}] shutting down connection", addr);
        // Drop the Arc so that the stream properly closes.
        drop(arc_stream);
        let _ = self.stream.shutdown(Shutdown::Both);
        if let Err(err) = child.join().expect("receiver panicked") {
            error!("[{}] receiver failed: {}", addr, err);
        }
    }
}

#[inline]
fn invalid_json_rpc(input: impl core::fmt::Display) -> Value {
    json!({
        "error": {
            "code": -32600,
            "message": format!("invalid request: {input}")
        },
        "id": null,
        "jsonrpc": "2.0"
    })
}

fn get_history(
    query: &Query,
    scripthash: &[u8],
    txs_limit: usize,
) -> Result<Vec<(Txid, Option<BlockId>)>> {
    // to avoid silently trunacting history entries, ask for one extra more than the limit and fail if it exists
    let history_txids = query.history_txids(scripthash, txs_limit + 1);
    ensure!(
        history_txids.len() <= txs_limit,
        ErrorKind::TooManyTxs(txs_limit)
    );
    Ok(history_txids)
}

#[derive(Serialize, Debug)]
struct GetHistoryResult {
    #[serde(rename = "tx_hash")]
    txid: Txid,
    height: isize,
    #[serde(skip_serializing_if = "Option::is_none")]
    fee: Option<u64>,
}

#[derive(Debug)]
pub enum Message {
    Request(String),
    PeriodicUpdate,
    Done,
}

pub enum Notification {
    Periodic,
    Exit,
}

pub struct RPC {
    notification: Sender<Notification>,
    server: Option<thread::JoinHandle<()>>, // so we can join the server while dropping this ojbect
}

struct Stats {
    latency: HistogramVec,
    clients: Gauge,
    subscriptions: Gauge,
}

impl RPC {
    fn start_notifier(
        notification: Channel<Notification>,
        senders: Arc<Mutex<Vec<crossbeam_channel::Sender<Message>>>>,
        acceptor: Sender<Option<ConnectionStream>>,
        acceptor_shutdown: Sender<()>,
    ) {
        spawn_thread("notification", move || {
            for msg in notification.receiver().iter() {
                let mut senders = senders.lock().unwrap();
                match msg {
                    Notification::Periodic => {
                        for sender in senders.split_off(0) {
                            if let Err(crossbeam_channel::TrySendError::Disconnected(_)) =
                                sender.try_send(Message::PeriodicUpdate)
                            {
                                continue;
                            }
                            senders.push(sender);
                        }
                    }
                    Notification::Exit => {
                        acceptor_shutdown.send(()).unwrap(); // Stop the acceptor itself
                        acceptor.send(None).unwrap(); // mark acceptor as done
                        break;
                    }
                }
            }
        });
    }

    fn start_acceptor(
        config: Arc<Config>,
        shutdown_channel: Channel<()>,
    ) -> Channel<Option<ConnectionStream>> {
        let chan = Channel::unbounded();
        let acceptor = chan.sender();
        spawn_thread("acceptor", move || {
            let addr = config.electrum_rpc_addr;
            let listener = if let Some(path) = config.rpc_socket_file.as_ref() {
                // We can leak this Path because we know that this function is only
                // called once on startup.
                let path: &'static Path = Box::leak(path.clone().into_boxed_path());

                ConnectionListener::new_unix(path)
            } else {
                debug!("Starting Electrum RPC server on {}", addr);
                ConnectionListener::new_tcp(&addr)
            };
            listener.run(acceptor, shutdown_channel);
        });
        chan
    }

    pub fn start(config: Arc<Config>, query: Arc<Query>, metrics: &Metrics) -> RPC {
        let stats = Arc::new(Stats {
            latency: metrics.histogram_vec(
                HistogramOpts::new("electrum_rpc", "Electrum RPC latency (seconds)"),
                &["method"],
            ),
            clients: metrics.gauge(MetricOpts::new("electrum_clients", "# of Electrum clients")),
            subscriptions: metrics.gauge(MetricOpts::new(
                "electrum_subscriptions",
                "# of Electrum subscriptions",
            )),
        });
        stats.clients.set(0);
        stats.subscriptions.set(0);

        let notification = Channel::unbounded();

        // Discovery is enabled when electrum-public-hosts is set
        #[cfg(feature = "electrum-discovery")]
        let discovery = config.electrum_public_hosts.clone().map(|hosts| {
            use crate::chain::genesis_hash;
            let features = ServerFeatures {
                hosts,
                server_version: VERSION_STRING.clone(),
                genesis_hash: genesis_hash(config.network_type),
                protocol_min: PROTOCOL_VERSION,
                protocol_max: PROTOCOL_VERSION,
                hash_function: "sha256".into(),
                pruning: None,
            };
            let discovery = Arc::new(DiscoveryManager::new(
                config.network_type,
                features,
                PROTOCOL_VERSION,
                config.electrum_announce,
                config.tor_proxy,
            ));
            DiscoveryManager::spawn_jobs_thread(Arc::clone(&discovery));
            discovery
        });

        let txs_limit = config.electrum_txs_limit;

        RPC {
            notification: notification.sender(),
            server: Some(spawn_thread("rpc", move || {
                let senders =
                    Arc::new(Mutex::new(Vec::<crossbeam_channel::Sender<Message>>::new()));

                let acceptor_shutdown = Channel::unbounded();
                let acceptor_shutdown_sender = acceptor_shutdown.sender();
                let acceptor = RPC::start_acceptor(config, acceptor_shutdown);
                RPC::start_notifier(
                    notification,
                    senders.clone(),
                    acceptor.sender(),
                    acceptor_shutdown_sender,
                );

                let mut threads = HashMap::new();
                let (garbage_sender, garbage_receiver) = crossbeam_channel::unbounded();

                while let Some(stream) = acceptor.receiver().recv().unwrap() {
                    let addr = stream.addr_string();
                    // explicitely scope the shadowed variables for the new thread
                    let query = Arc::clone(&query);
                    let senders = Arc::clone(&senders);
                    let stats = Arc::clone(&stats);
                    let garbage_sender = garbage_sender.clone();

                    // Kill the peers properly
                    let (killer, peace_receiver) = std::sync::mpsc::channel();
                    let killer_clone = killer.clone();

                    #[cfg(feature = "electrum-discovery")]
                    let discovery = discovery.clone();

                    let spawned = spawn_thread("peer", move || {
                        let addr = stream.addr_string();
                        info!("[{}] connected peer", addr);
                        let conn = Connection::new(
                            query,
                            stream,
                            stats,
                            txs_limit,
                            peace_receiver,
                            #[cfg(feature = "electrum-discovery")]
                            discovery,
                        );
                        senders.lock().unwrap().push(conn.chan.sender());
                        conn.run();
                        info!("[{}] disconnected peer", addr);
                        let _ = killer_clone.send(());
                        let _ = garbage_sender.send(std::thread::current().id());
                    });

                    trace!("[{}] spawned {:?}", addr, spawned.thread().id());
                    threads.insert(spawned.thread().id(), (spawned, killer));
                    while let Ok(id) = garbage_receiver.try_recv() {
                        if let Some((thread, killer)) = threads.remove(&id) {
                            trace!("[{}] joining {:?}", addr, id);
                            let _ = killer.send(());
                            if let Err(error) = thread.join() {
                                error!("failed to join {:?}: {:?}", id, error);
                            }
                        }
                    }
                }
                // Drop these
                drop(acceptor);
                drop(garbage_receiver);

                trace!("closing {} RPC connections", senders.lock().unwrap().len());
                for sender in senders.lock().unwrap().iter() {
                    let _ = sender.try_send(Message::Done);
                }

                for (id, (thread, killer)) in threads {
                    trace!("joining {:?}", id);
                    let _ = killer.send(());
                    if let Err(error) = thread.join() {
                        error!("failed to join {:?}: {:?}", id, error);
                    }
                }

                trace!("RPC connections are closed");
            })),
        }
    }

    pub fn notify(&self) {
        self.notification.send(Notification::Periodic).unwrap();
    }
}

impl Drop for RPC {
    fn drop(&mut self) {
        trace!("stop accepting new RPCs");
        self.notification.send(Notification::Exit).unwrap();
        if let Some(handle) = self.server.take() {
            handle.join().unwrap();
        }
        trace!("RPC server is stopped");
        crate::util::with_spawned_threads(|threads| {
            trace!("Threads after dropping RPC: {:?}", threads);
        });
    }
}

enum ConnectionListener {
    Tcp(TcpListener),
    Unix(UnixListener, &'static Path),
}

impl ConnectionListener {
    fn new_tcp(addr: &SocketAddr) -> Self {
        let socket = create_socket(addr);
        socket.listen(511).expect("setting backlog failed");
        socket
            .set_nonblocking(false)
            .expect("cannot set nonblocking to false");
        info!("Electrum RPC server running on {}", addr);
        Self::Tcp(TcpListener::from(socket))
    }

    /// This takes a static reference to a Path in order to
    /// make shallow clones of UnixStreams much cheaper.
    /// Since this type will only usually be instanciated 1 time
    /// it should be acceptable to just leak the PathBuf.
    /// Do not leak values if you call this an unknown number of
    /// times throughout the program.
    fn new_unix(path: &'static Path) -> Self {
        if let Ok(meta) = fs::metadata(path) {
            // Cleanup socket file left by previous execution
            if meta.file_type().is_socket() {
                fs::remove_file(path).ok();
            }
        }

        let socket = std::os::unix::net::UnixListener::bind(path)
            .expect("cannnot bind to unix socket for RPC");
        socket
            .set_nonblocking(false)
            .expect("cannot set nonblocking to false");
        info!(
            "Electrum RPC server running on unix socket {}",
            path.display()
        );
        Self::Unix(socket, path)
    }

    fn run(&self, acceptor: Sender<Option<ConnectionStream>>, shutdown_channel: Channel<()>) {
        let shutdown_bool = Arc::new(AtomicBool::new(false));

        {
            let shutdown_bool = Arc::clone(&shutdown_bool);
            crate::util::spawn_thread(
                "shutdown-acceptor",
                self.create_shutdown_job(shutdown_channel, shutdown_bool),
            );
        }

        loop {
            let stream = self.accept().expect("accept failed");

            if shutdown_bool.load(std::sync::atomic::Ordering::Acquire) {
                break;
            }

            stream
                .set_nonblocking(false)
                .expect("failed to set connection as blocking");
            acceptor.send(Some(stream)).expect("send failed");
        }
    }

    fn accept(&self) -> std::result::Result<ConnectionStream, std::io::Error> {
        match self {
            Self::Tcp(c) => c.accept().map(|(l, r)| ConnectionStream::Tcp(l, r)),
            Self::Unix(c, p) => c.accept().map(|(l, r)| ConnectionStream::Unix(l, r, p)),
        }
    }

    fn create_shutdown_job(
        &self,
        shutdown_channel: Channel<()>,
        shutdown_bool: Arc<AtomicBool>,
    ) -> Box<dyn FnOnce() + Send + 'static> {
        match self {
            ConnectionListener::Tcp(c) => {
                let local_addr = c.local_addr().unwrap();
                Box::new(move || {
                    // Block until shutdown is sent.
                    let _ = shutdown_channel.receiver().recv();
                    // Store the bool so after the next accept it will break the loop
                    shutdown_bool.store(true, std::sync::atomic::Ordering::Release);
                    // Connect to the socket to cause it to unblock
                    let _ = TcpStream::connect(local_addr);
                })
            }
            ConnectionListener::Unix(_, p) => {
                let path = *p;
                Box::new(move || {
                    // Block until shutdown is sent.
                    let _ = shutdown_channel.receiver().recv();
                    // Store the bool so after the next accept it will break the loop
                    shutdown_bool.store(true, std::sync::atomic::Ordering::Release);
                    // Connect to the socket to cause it to unblock
                    let _ = UnixStream::connect(path);
                })
            }
        }
    }
}

enum ConnectionStream {
    Tcp(TcpStream, std::net::SocketAddr),
    Unix(UnixStream, std::os::unix::net::SocketAddr, &'static Path),
}

impl ConnectionStream {
    fn addr_string(&self) -> String {
        match self {
            ConnectionStream::Tcp(_, a) => format!("{a}"),
            ConnectionStream::Unix(_, a, _) => format!("{a:?}"),
        }
    }

    fn try_clone(&self) -> std::io::Result<Self> {
        Ok(match self {
            ConnectionStream::Tcp(s, a) => ConnectionStream::Tcp(s.try_clone()?, *a),
            ConnectionStream::Unix(s, a, p) => ConnectionStream::Unix(s.try_clone()?, a.clone(), p),
        })
    }

    fn shutdown(&self, how: Shutdown) -> std::io::Result<()> {
        match self {
            ConnectionStream::Tcp(s, _) => s.shutdown(how),
            ConnectionStream::Unix(s, _, _) => s.shutdown(how),
        }
    }

    fn set_nonblocking(&self, nonblocking: bool) -> std::io::Result<()> {
        match self {
            ConnectionStream::Tcp(s, _) => s.set_nonblocking(nonblocking),
            ConnectionStream::Unix(s, _, _) => s.set_nonblocking(nonblocking),
        }
    }

    #[cfg(feature = "electrum-discovery")]
    fn ip(&self) -> Option<IpAddr> {
        match self {
            ConnectionStream::Tcp(_, a) => Some(a.ip()),
            ConnectionStream::Unix(_, _, _) => None,
        }
    }
}

impl Write for ConnectionStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            ConnectionStream::Tcp(s, _) => s.write(buf),
            ConnectionStream::Unix(s, _, _) => s.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            ConnectionStream::Tcp(s, _) => s.flush(),
            ConnectionStream::Unix(s, _, _) => s.flush(),
        }
    }
}

impl Read for ConnectionStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            ConnectionStream::Tcp(s, _) => s.read(buf),
            ConnectionStream::Unix(s, _, _) => s.read(buf),
        }
    }
}
