use std::sync::{Arc, RwLock};

use bitcoin::{consensus::serialize, VarInt};
use prometheus::{HistogramOpts, HistogramTimer, HistogramVec};

use crate::{
    chain::{BlockHash, BlockHeader, Network, OutPoint, Transaction, TxOut, Txid, Value},
    config::Config,
    daemon::Daemon,
    metrics::Metrics,
    new_index::{BlockRow, ScanIterator, Store, TxHistoryRow},
    util::{bincode_util, full_hash, BlockHeaderMeta, BlockMeta},
};

const MIN_HISTORY_ITEMS_TO_CACHE: usize = 100;

pub struct ChainQuery {
    store: Arc<Store>, // TODO: should be used as read-only
    daemon: Arc<Daemon>,
    light_mode: bool,
    duration: HistogramVec,
    network: Network,
}

impl ChainQuery {
    pub fn new(store: Arc<Store>, daemon: Arc<Daemon>, config: &Config, metrics: &Metrics) -> Self {
        ChainQuery {
            store,
            daemon,
            light_mode: config.light_mode,
            network: config.network_type,
            duration: metrics.histogram_vec(
                HistogramOpts::new("query_duration", "Index query duration (in seconds)"),
                &["name"],
            ),
        }
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    fn start_timer(&self, name: &str) -> HistogramTimer {
        self.duration.with_label_values(&[name]).start_timer()
    }

    pub fn get_block_txids(&self, hash: &BlockHash) -> Option<Vec<Txid>> {
        let _timer = self.start_timer("get_block_txids");

        if self.light_mode {
            // TODO fetch block as binary from REST API instead of as hex
            let mut blockinfo = self.daemon.getblock_raw(hash, 1).ok()?;
            Some(serde_json::from_value(blockinfo["tx"].take()).unwrap())
        } else {
            self.store
                .txstore_db()
                .get(&BlockRow::txids_key(full_hash(&hash[..])))
                .map(|val| {
                    bincode_util::deserialize_little(&val).expect("failed to parse block txids")
                })
        }
    }

    pub fn get_block_txs(&self, hash: &BlockHash) -> Option<Vec<Transaction>> {
        let _timer = self.start_timer("get_block_txs");

        let txids: Option<Vec<Txid>> = if self.light_mode {
            // TODO fetch block as binary from REST API instead of as hex
            let mut blockinfo = self.daemon.getblock_raw(hash, 1).ok()?;
            Some(serde_json::from_value(blockinfo["tx"].take()).unwrap())
        } else {
            self.store
                .txstore_db()
                .get(&BlockRow::txids_key(full_hash(&hash[..])))
                .map(|val| {
                    bincode_util::deserialize_little(&val).expect("failed to parse block txids")
                })
        };

        txids.and_then(|txid_vec| {
            let mut transactions = Vec::with_capacity(txid_vec.len());

            for txid in txid_vec {
                match self.lookup_txn(&txid, Some(hash)) {
                    Some(transaction) => transactions.push(transaction),
                    None => return None,
                }
            }

            Some(transactions)
        })
    }

    pub fn get_block_meta(&self, hash: &BlockHash) -> Option<BlockMeta> {
        let _timer = self.start_timer("get_block_meta");

        if self.light_mode {
            let blockinfo = self.daemon.getblock_raw(hash, 1).ok()?;
            Some(serde_json::from_value(blockinfo).unwrap())
        } else {
            self.store
                .txstore_db()
                .get(&BlockRow::meta_key(full_hash(&hash[..])))
                .map(|val| {
                    bincode_util::deserialize_little(&val).expect("failed to parse BlockMeta")
                })
        }
    }

    pub fn get_block_raw(&self, hash: &BlockHash) -> Option<Vec<u8>> {
        let _timer = self.start_timer("get_block_raw");

        if self.light_mode {
            let blockhex = self.daemon.getblock_raw(hash, 0).ok()?;
            Some(hex::decode(blockhex.as_str().unwrap()).unwrap())
        } else {
            let entry = self.header_by_hash(hash)?;
            let meta = self.get_block_meta(hash)?;
            let txids = self.get_block_txids(hash)?;

            // Reconstruct the raw block using the header and txids,
            // as <raw header><tx count varint><raw txs>
            let mut raw = Vec::with_capacity(meta.size as usize);

            raw.append(&mut serialize(entry.header()));
            raw.append(&mut serialize(&VarInt(txids.len() as u64)));

            for txid in txids {
                // we don't need to provide the blockhash because we know we're not in light mode
                raw.append(&mut self.lookup_raw_txn(&txid, None)?);
            }

            Some(raw)
        }
    }

    pub fn get_block_header(&self, hash: &BlockHash) -> Option<BlockHeader> {
        let _timer = self.start_timer("get_block_header");
        #[allow(clippy::clone_on_copy)]
        Some(self.header_by_hash(hash)?.header().clone())
    }

    pub fn get_mtp(&self, height: usize) -> u32 {
        let _timer = self.start_timer("get_block_mtp");
        self.store.indexed_headers().read().unwrap().get_mtp(height)
    }

    pub fn get_block_with_meta(&self, hash: &BlockHash) -> Option<BlockHeaderMeta> {
        let _timer = self.start_timer("get_block_with_meta");
        let header_entry = self.header_by_hash(hash)?;
        Some(BlockHeaderMeta {
            meta: self.get_block_meta(hash)?,
            mtp: self.get_mtp(header_entry.height()),
            header_entry,
        })
    }

    pub fn history_iter_scan(&self, code: u8, hash: &[u8], start_height: usize) -> ScanIterator {
        self.store.history_db.iter_scan_from(
            &TxHistoryRow::filter(code, hash),
            &TxHistoryRow::prefix_height(code, hash, start_height as u32),
        )
    }
    fn history_iter_scan_reverse(
        &self,
        code: u8,
        hash: &[u8],
        start_height: Option<u32>,
    ) -> ReverseScanIterator {
        self.store.history_db.iter_scan_reverse(
            &TxHistoryRow::filter(code, hash),
            &start_height.map_or(TxHistoryRow::prefix_end(code, hash), |start_height| {
                TxHistoryRow::prefix_height_end(code, hash, start_height)
            }),
        )
    }
    fn history_iter_scan_group_reverse(
        &self,
        code: u8,
        hashes: &[[u8; 32]],
        start_height: Option<u32>,
    ) -> ReverseScanGroupIterator {
        self.store.history_db.iter_scan_group_reverse(
            hashes.iter().map(|hash| {
                let prefix = TxHistoryRow::filter(code, &hash[..]);
                let prefix_max = start_height
                    .map_or(TxHistoryRow::prefix_end(code, &hash[..]), |start_height| {
                        TxHistoryRow::prefix_height_end(code, &hash[..], start_height)
                    });
                (prefix, prefix_max)
            }),
            33,
        )
    }

    fn collate_summaries(
        &self,
        iter: impl Iterator<Item = TxHistoryRow>,
        last_seen_txid: Option<&Txid>,
        limit: usize,
    ) -> Vec<TxHistorySummary> {
        // collate utxo funding/spending events by transaction

        let rows = iter
            .map(|row| (row.get_txid(), row.key.txinfo, row.key.tx_position))
            .skip_while(|(txid, _, _)| {
                // skip until we reach the last_seen_txid
                last_seen_txid.map_or(false, |last_seen_txid| last_seen_txid != txid)
            })
            .skip_while(|(txid, _, _)| {
                // skip the last_seen_txid itself
                last_seen_txid.map_or(false, |last_seen_txid| last_seen_txid == txid)
            })
            .filter_map(|(txid, info, tx_position)| {
                self.tx_confirming_block(&txid)
                    .map(|b| (txid, info, b.height, b.time, tx_position))
            });
        let mut map: HashMap<Txid, TxHistorySummary> = HashMap::new();
        for (txid, info, height, time, tx_position) in rows {
            if !map.contains_key(&txid) && map.len() == limit {
                break;
            }
            match info {
                #[cfg(not(feature = "liquid"))]
                TxHistoryInfo::Funding(info) => {
                    map.entry(txid)
                        .and_modify(|tx| {
                            tx.value = tx.value.saturating_add(info.value.try_into().unwrap_or(0))
                        })
                        .or_insert(TxHistorySummary {
                            txid,
                            value: info.value.try_into().unwrap_or(0),
                            height,
                            time,
                            tx_position,
                        });
                }
                #[cfg(not(feature = "liquid"))]
                TxHistoryInfo::Spending(info) => {
                    map.entry(txid)
                        .and_modify(|tx| {
                            tx.value = tx.value.saturating_sub(info.value.try_into().unwrap_or(0))
                        })
                        .or_insert(TxHistorySummary {
                            txid,
                            value: 0_i64.saturating_sub(info.value.try_into().unwrap_or(0)),
                            height,
                            time,
                            tx_position,
                        });
                }
                #[cfg(feature = "liquid")]
                TxHistoryInfo::Funding(_info) => {
                    map.entry(txid).or_insert(TxHistorySummary {
                        txid,
                        value: 0,
                        height,
                        time,
                        tx_position,
                    });
                }
                #[cfg(feature = "liquid")]
                TxHistoryInfo::Spending(_info) => {
                    map.entry(txid).or_insert(TxHistorySummary {
                        txid,
                        value: 0,
                        height,
                        time,
                        tx_position,
                    });
                }
                #[cfg(feature = "liquid")]
                _ => {}
            }
        }
        let mut tx_summaries = map.into_values().collect::<Vec<TxHistorySummary>>();
        tx_summaries.sort_by(|a, b| {
            if a.height == b.height {
                if a.tx_position == b.tx_position {
                    a.value.cmp(&b.value)
                } else {
                    b.tx_position.cmp(&a.tx_position)
                }
            } else {
                b.height.cmp(&a.height)
            }
        });
        tx_summaries
    }

    pub fn summary(
        &self,
        scripthash: &[u8],
        last_seen_txid: Option<&Txid>,
        start_height: Option<u32>,
        limit: usize,
    ) -> Vec<TxHistorySummary> {
        // scripthash lookup
        self._summary(b'H', scripthash, last_seen_txid, start_height, limit)
    }

    fn _summary(
        &self,
        code: u8,
        hash: &[u8],
        last_seen_txid: Option<&Txid>,
        start_height: Option<u32>,
        limit: usize,
    ) -> Vec<TxHistorySummary> {
        let _timer_scan = self.start_timer("address_summary");
        let rows = self
            .history_iter_scan_reverse(code, hash, start_height)
            .map(TxHistoryRow::from_row);

        self.collate_summaries(rows, last_seen_txid, limit)
    }

    pub fn summary_group(
        &self,
        scripthashes: &[[u8; 32]],
        last_seen_txid: Option<&Txid>,
        start_height: Option<u32>,
        limit: usize,
    ) -> Vec<TxHistorySummary> {
        // scripthash lookup
        let _timer_scan = self.start_timer("address_group_summary");
        let rows = self
            .history_iter_scan_group_reverse(b'H', scripthashes, start_height)
            .map(TxHistoryRow::from_row);

        self.collate_summaries(rows, last_seen_txid, limit)
    }

    pub fn history<'a>(
        &'a self,
        scripthash: &[u8],
        last_seen_txid: Option<&'a Txid>,
        start_height: Option<u32>,
        limit: usize,
    ) -> impl rayon::iter::ParallelIterator<Item = Result<(Transaction, BlockId)>> + 'a {
        // scripthash lookup
        self._history(b'H', scripthash, last_seen_txid, start_height, limit)
    }

    pub fn history_txids_iter<'a>(&'a self, scripthash: &[u8]) -> impl Iterator<Item = Txid> + 'a {
        self.history_iter_scan_reverse(b'H', scripthash, None)
            .map(|row| TxHistoryRow::from_row(row).get_txid())
            .unique()
    }

    fn _history<'a>(
        &'a self,
        code: u8,
        hash: &[u8],
        last_seen_txid: Option<&'a Txid>,
        start_height: Option<u32>,
        limit: usize,
    ) -> impl rayon::iter::ParallelIterator<Item = Result<(Transaction, BlockId)>> + 'a {
        let _timer_scan = self.start_timer("history");

        self.lookup_txns(
            self.history_iter_scan_reverse(code, hash, start_height)
                .map(|row| TxHistoryRow::from_row(row).get_txid())
                // XXX: unique() requires keeping an in-memory list of all txids, can we avoid that?
                .unique()
                // TODO seek directly to last seen tx without reading earlier rows
                .skip_while(move |txid| {
                    // skip until we reach the last_seen_txid
                    last_seen_txid.map_or(false, |last_seen_txid| last_seen_txid != txid)
                })
                .skip(match last_seen_txid {
                    Some(_) => 1, // skip the last_seen_txid itself
                    None => 0,
                })
                .filter_map(move |txid| self.tx_confirming_block(&txid).map(|b| (txid, b))),
            limit,
        )
    }

    pub fn history_txids(&self, scripthash: &[u8], limit: usize) -> Vec<(Txid, BlockId)> {
        // scripthash lookup
        self._history_txids(b'H', scripthash, limit)
    }

    fn _history_txids(&self, code: u8, hash: &[u8], limit: usize) -> Vec<(Txid, BlockId)> {
        let _timer = self.start_timer("history_txids");
        self.history_iter_scan(code, hash, 0)
            .map(|row| TxHistoryRow::from_row(row).get_txid())
            .unique()
            .filter_map(|txid| self.tx_confirming_block(&txid).map(|b| (txid, b)))
            .take(limit)
            .collect()
    }

    pub fn history_group<'a>(
        &'a self,
        scripthashes: &[[u8; 32]],
        last_seen_txid: Option<&'a Txid>,
        start_height: Option<u32>,
        limit: usize,
    ) -> impl rayon::iter::ParallelIterator<Item = Result<(Transaction, BlockId)>> + 'a {
        // scripthash lookup
        self._history_group(b'H', scripthashes, last_seen_txid, start_height, limit)
    }

    pub fn history_txids_iter_group(
        &self,
        scripthashes: &[[u8; 32]],
        start_height: Option<u32>,
    ) -> impl Iterator<Item = Txid> + '_ {
        self.history_iter_scan_group_reverse(b'H', scripthashes, start_height)
            .map(|row| TxHistoryRow::from_row(row).get_txid())
            .unique()
    }

    fn _history_group<'a>(
        &'a self,
        code: u8,
        hashes: &[[u8; 32]],
        last_seen_txid: Option<&'a Txid>,
        start_height: Option<u32>,
        limit: usize,
    ) -> impl rayon::iter::ParallelIterator<Item = Result<(Transaction, BlockId)>> + 'a {
        debug!("limit {} | last_seen {:?}", limit, last_seen_txid);
        let _timer_scan = self.start_timer("history_group");

        self.lookup_txns(
            self.history_iter_scan_group_reverse(code, hashes, start_height)
                .map(|row| TxHistoryRow::from_row(row).get_txid())
                // XXX: unique() requires keeping an in-memory list of all txids, can we avoid that?
                .unique()
                .skip_while(move |txid| {
                    // we already seeked to the last txid at this height
                    // now skip just past the last_seen_txid itself
                    last_seen_txid.map_or(false, |last_seen_txid| last_seen_txid != txid)
                })
                .skip(match last_seen_txid {
                    Some(_) => 1, // skip the last_seen_txid itself
                    None => 0,
                })
                .filter_map(move |txid| self.tx_confirming_block(&txid).map(|b| (txid, b))),
            limit,
        )
    }

    // TODO: avoid duplication with stats/stats_delta?
    pub fn utxo(&self, scripthash: &[u8], limit: usize, flush: DBFlush) -> Result<Vec<Utxo>> {
        let _timer = self.start_timer("utxo");

        // get the last known utxo set and the blockhash it was updated for.
        // invalidates the cache if the block was orphaned.
        let cache: Option<(UtxoMap, usize)> = self
            .store
            .cache_db
            .get(&UtxoCacheRow::key(scripthash))
            .map(|c| bincode_util::deserialize_little(&c).unwrap())
            .and_then(|(utxos_cache, blockhash)| {
                self.height_by_hash(&blockhash)
                    .map(|height| (utxos_cache, height))
            })
            .map(|(utxos_cache, height)| (from_utxo_cache(utxos_cache, self), height));
        let had_cache = cache.is_some();

        // update utxo set with new transactions since
        let (newutxos, lastblock, processed_items) = cache.map_or_else(
            || self.utxo_delta(scripthash, HashMap::new(), 0, limit),
            |(oldutxos, blockheight)| self.utxo_delta(scripthash, oldutxos, blockheight + 1, limit),
        )?;

        // save updated utxo set to cache
        if let Some(lastblock) = lastblock {
            if had_cache || processed_items > MIN_HISTORY_ITEMS_TO_CACHE {
                self.store.cache_db.write(
                    vec![UtxoCacheRow::new(scripthash, &newutxos, &lastblock).into_row()],
                    flush,
                );
            }
        }

        // format as Utxo objects
        Ok(newutxos
            .into_iter()
            .map(|(outpoint, (blockid, value))| {
                // in elements/liquid chains, we have to lookup the txo in order to get its
                // associated asset. the asset information could be kept in the db history rows
                // alongside the value to avoid this.
                #[cfg(feature = "liquid")]
                let txo = self.lookup_txo(&outpoint).expect("missing utxo");

                Utxo {
                    txid: outpoint.txid,
                    vout: outpoint.vout,
                    value,
                    confirmed: Some(blockid),

                    #[cfg(feature = "liquid")]
                    asset: txo.asset,
                    #[cfg(feature = "liquid")]
                    nonce: txo.nonce,
                    #[cfg(feature = "liquid")]
                    witness: txo.witness,
                }
            })
            .collect())
    }

    fn utxo_delta(
        &self,
        scripthash: &[u8],
        init_utxos: UtxoMap,
        start_height: usize,
        limit: usize,
    ) -> Result<(UtxoMap, Option<BlockHash>, usize)> {
        let _timer = self.start_timer("utxo_delta");
        let history_iter = self
            .history_iter_scan(b'H', scripthash, start_height)
            .map(TxHistoryRow::from_row)
            .filter_map(|history| {
                self.tx_confirming_block(&history.get_txid())
                    // drop history entries that were previously confirmed in a re-orged block and later
                    // confirmed again at a different height
                    .filter(|blockid| blockid.height == history.key.confirmed_height as usize)
                    .map(|b| (history, b))
            });

        let mut utxos = init_utxos;
        let mut processed_items = 0;
        let mut lastblock = None;

        for (history, blockid) in history_iter {
            processed_items += 1;
            lastblock = Some(blockid.hash);

            match history.key.txinfo {
                TxHistoryInfo::Funding(ref info) => {
                    utxos.insert(history.get_funded_outpoint(), (blockid, info.value))
                }
                TxHistoryInfo::Spending(_) => utxos.remove(&history.get_funded_outpoint()),
                #[cfg(feature = "liquid")]
                TxHistoryInfo::Issuing(_)
                | TxHistoryInfo::Burning(_)
                | TxHistoryInfo::Pegin(_)
                | TxHistoryInfo::Pegout(_) => unreachable!(),
            };

            // abort if the utxo set size excedees the limit at any point in time
            if utxos.len() > limit {
                bail!(ErrorKind::TooManyUtxos(limit))
            }
        }

        Ok((utxos, lastblock, processed_items))
    }

    pub fn stats(&self, scripthash: &[u8], flush: DBFlush) -> ScriptStats {
        let _timer = self.start_timer("stats");

        // get the last known stats and the blockhash they are updated for.
        // invalidates the cache if the block was orphaned or if values are out of sync.
        let cache: Option<(ScriptStats, usize)> = self
            .store
            .cache_db
            .get(&StatsCacheRow::key(scripthash))
            .map(|c| bincode_util::deserialize_little::<(ScriptStats, BlockHash)>(&c).unwrap())
            // Check that the values are sane (No negative balances or balances with 0 utxos)
            .filter(|(stats, _)| stats.is_sane())
            .and_then(|(stats, blockhash)| {
                self.height_by_hash(&blockhash)
                    .map(|height| (stats, height))
            });

        // update stats with new transactions since
        let (newstats, lastblock) = cache.map_or_else(
            || self.stats_delta(scripthash, ScriptStats::default(), 0),
            |(oldstats, blockheight)| self.stats_delta(scripthash, oldstats, blockheight + 1),
        );

        // save updated stats to cache
        if let Some(lastblock) = lastblock {
            if newstats.funded_txo_count + newstats.spent_txo_count > MIN_HISTORY_ITEMS_TO_CACHE {
                self.store.cache_db.write(
                    vec![StatsCacheRow::new(scripthash, &newstats, &lastblock).into_row()],
                    flush,
                );
            }
        }

        newstats
    }

    fn stats_delta(
        &self,
        scripthash: &[u8],
        init_stats: ScriptStats,
        start_height: usize,
    ) -> (ScriptStats, Option<BlockHash>) {
        let _timer = self.start_timer("stats_delta"); // TODO: measure also the number of txns processed.
        let history_iter = self
            .history_iter_scan(b'H', scripthash, start_height)
            .map(TxHistoryRow::from_row)
            .filter_map(|history| {
                self.tx_confirming_block(&history.get_txid())
                    // drop history entries that were previously confirmed in a re-orged block and later
                    // confirmed again at a different height
                    .filter(|blockid| blockid.height == history.key.confirmed_height as usize)
                    .map(|blockid| (history, blockid))
            });

        let mut stats = init_stats;
        let mut seen_txids = HashSet::new();
        let mut lastblock = None;

        for (history, blockid) in history_iter {
            if lastblock != Some(blockid.hash) {
                seen_txids.clear();
            }

            if seen_txids.insert(history.get_txid()) {
                stats.tx_count += 1;
            }

            match history.key.txinfo {
                #[cfg(not(feature = "liquid"))]
                TxHistoryInfo::Funding(ref info) => {
                    stats.funded_txo_count += 1;
                    stats.funded_txo_sum += info.value;
                }

                #[cfg(not(feature = "liquid"))]
                TxHistoryInfo::Spending(ref info) => {
                    stats.spent_txo_count += 1;
                    stats.spent_txo_sum += info.value;
                }

                #[cfg(feature = "liquid")]
                TxHistoryInfo::Funding(_) => {
                    stats.funded_txo_count += 1;
                }

                #[cfg(feature = "liquid")]
                TxHistoryInfo::Spending(_) => {
                    stats.spent_txo_count += 1;
                }

                #[cfg(feature = "liquid")]
                TxHistoryInfo::Issuing(_)
                | TxHistoryInfo::Burning(_)
                | TxHistoryInfo::Pegin(_)
                | TxHistoryInfo::Pegout(_) => unreachable!(),
            }

            lastblock = Some(blockid.hash);
        }

        (stats, lastblock)
    }

    pub fn address_search(&self, prefix: &str, limit: usize) -> Vec<String> {
        let _timer_scan = self.start_timer("address_search");
        self.store
            .history_db
            .iter_scan(&addr_search_filter(prefix))
            .take(limit)
            .map(|row| std::str::from_utf8(&row.key[1..]).unwrap().to_string())
            .collect()
    }

    fn header_by_hash(&self, hash: &BlockHash) -> Option<HeaderEntry> {
        self.store
            .indexed_headers()
            .read()
            .unwrap()
            .header_by_blockhash(hash)
    }

    // Get the height of a blockhash, only if its part of the best chain
    pub fn height_by_hash(&self, hash: &BlockHash) -> Option<usize> {
        self.store
            .indexed_headers()
            .read()
            .unwrap()
            .header_by_blockhash(hash)
            .map(|header| header.height())
    }

    pub fn header_by_height(&self, height: usize) -> Option<HeaderEntry> {
        self.store
            .indexed_headers()
            .read()
            .unwrap()
            .header_by_height(height)
    }

    pub fn hash_by_height(&self, height: usize) -> Option<BlockHash> {
        self.store
            .indexed_headers()
            .read()
            .unwrap()
            .header_by_height(height)
            .map(|entry| *entry.hash())
    }

    pub fn blockid_by_height(&self, height: usize) -> Option<BlockId> {
        self.store
            .indexed_headers()
            .read()
            .unwrap()
            .header_by_height(height)
            .map(BlockId::from)
    }

    // returns None for orphaned blocks
    pub fn blockid_by_hash(&self, hash: &BlockHash) -> Option<BlockId> {
        self.store
            .indexed_headers()
            .read()
            .unwrap()
            .header_by_blockhash(hash)
            .map(BlockId::from)
    }

    pub fn best_height(&self) -> usize {
        self.store.indexed_headers().read().unwrap().len() - 1
    }

    pub fn best_hash(&self) -> BlockHash {
        *self.store.indexed_headers().read().unwrap().tip()
    }

    pub fn best_header(&self) -> HeaderEntry {
        let headers = self.store.indexed_headers().read().unwrap();
        headers
            .header_by_blockhash(headers.tip())
            .expect("missing chain tip")
            .clone()
    }

    // TODO: can we pass txids as a "generic iterable"?
    // TODO: should also use a custom ThreadPoolBuilder?
    pub fn lookup_txns<'a, I>(
        &'a self,
        txids: I,
        take: usize,
    ) -> impl rayon::iter::ParallelIterator<Item = Result<(Transaction, BlockId)>> + 'a
    where
        I: Iterator<Item = (Txid, BlockId)> + Send + rayon::iter::ParallelBridge + 'a,
    {
        txids
            .take(take)
            .par_bridge()
            .map(move |(txid, blockid)| -> Result<_> {
                Ok((
                    self.lookup_txn(&txid, Some(&blockid.hash))
                        .chain_err(|| "missing tx")?,
                    blockid,
                ))
            })
    }

    pub fn lookup_txn(&self, txid: &Txid, blockhash: Option<&BlockHash>) -> Option<Transaction> {
        let _timer = self.start_timer("lookup_txn");
        self.lookup_raw_txn(txid, blockhash).map(|rawtx| {
            let txn: Transaction = deserialize(&rawtx).expect("failed to parse Transaction");
            assert_eq!(*txid, txn.compute_txid());
            txn
        })
    }

    pub fn lookup_raw_txn(&self, txid: &Txid, blockhash: Option<&BlockHash>) -> Option<Bytes> {
        let _timer = self.start_timer("lookup_raw_txn");

        if self.light_mode {
            let queried_blockhash =
                blockhash.map_or_else(|| self.tx_confirming_block(txid).map(|b| b.hash), |_| None);
            let blockhash = blockhash.or(queried_blockhash.as_ref())?;
            // TODO fetch transaction as binary from REST API instead of as hex
            let txhex = self
                .daemon
                .gettransaction_raw(txid, blockhash, false)
                .ok()?;
            Some(hex::decode(txhex.as_str().unwrap()).unwrap())
        } else {
            self.store.txstore_db.get(&TxRow::key(&txid[..]))
        }
    }

    pub fn lookup_txo(&self, outpoint: &OutPoint) -> Option<TxOut> {
        let _timer = self.start_timer("lookup_txo");
        lookup_txo(&self.store.txstore_db, outpoint)
    }

    pub fn lookup_txos(&self, outpoints: &BTreeSet<OutPoint>) -> HashMap<OutPoint, TxOut> {
        let _timer = self.start_timer("lookup_txos");
        lookup_txos(&self.store.txstore_db, outpoints, false)
    }

    pub fn lookup_avail_txos(&self, outpoints: &BTreeSet<OutPoint>) -> HashMap<OutPoint, TxOut> {
        let _timer = self.start_timer("lookup_available_txos");
        lookup_txos(&self.store.txstore_db, outpoints, true)
    }

    pub fn lookup_spend(&self, outpoint: &OutPoint) -> Option<SpendingInput> {
        let _timer = self.start_timer("lookup_spend");
        self.store
            .history_db
            .iter_scan(&TxEdgeRow::filter(outpoint))
            .map(TxEdgeRow::from_row)
            .find_map(|edge| {
                let txid: Txid = deserialize(&edge.key.spending_txid).unwrap();
                self.tx_confirming_block(&txid).map(|b| SpendingInput {
                    txid,
                    vin: edge.key.spending_vin,
                    confirmed: Some(b),
                })
            })
    }
    pub fn tx_confirming_block(&self, txid: &Txid) -> Option<BlockId> {
        let _timer = self.start_timer("tx_confirming_block");
        let headers = self.store.indexed_headers().read().unwrap();
        self.store
            .txstore_db
            .iter_scan(&TxConfRow::filter(&txid[..]))
            .map(TxConfRow::from_row)
            // header_by_blockhash only returns blocks that are part of the best chain,
            // or None for orphaned blocks.
            .filter_map(|conf| {
                headers.header_by_blockhash(&deserialize(&conf.key.blockhash).unwrap())
            })
            .next()
            .map(BlockId::from)
    }

    pub fn get_block_status(&self, hash: &BlockHash) -> BlockStatus {
        // TODO differentiate orphaned and non-existing blocks? telling them apart requires
        // an additional db read.

        let headers = self.store.indexed_headers().read().unwrap();

        // header_by_blockhash only returns blocks that are part of the best chain,
        // or None for orphaned blocks.
        headers
            .header_by_blockhash(hash)
            .map_or_else(BlockStatus::orphaned, |header| {
                BlockStatus::confirmed(
                    header.height(),
                    headers
                        .header_by_height(header.height() + 1)
                        .map(|h| *h.hash()),
                )
            })
    }

    #[cfg(not(feature = "liquid"))]
    pub fn get_merkleblock_proof(&self, txid: &Txid) -> Option<bitcoin::MerkleBlock> {
        use bitcoin::MerkleBlock;

        let _timer = self.start_timer("get_merkleblock_proof");
        let blockid = self.tx_confirming_block(txid)?;
        let headerentry = self.header_by_hash(&blockid.hash)?;
        let block_txids = self.get_block_txids(&blockid.hash)?;

        Some(MerkleBlock::from_header_txids_with_predicate(
            headerentry.header(),
            &block_txids,
            |t| t == txid,
        ))
    }

    #[cfg(feature = "liquid")]
    pub fn asset_history<'a>(
        &'a self,
        asset_id: &'a AssetId,
        last_seen_txid: Option<&'a Txid>,
        limit: usize,
    ) -> impl rayon::iter::ParallelIterator<Item = Result<(Transaction, BlockId)>> + 'a {
        self._history(
            b'I',
            &asset_id.into_inner()[..],
            last_seen_txid,
            None,
            limit,
        )
    }

    #[cfg(feature = "liquid")]
    pub fn asset_history_txids(&self, asset_id: &AssetId, limit: usize) -> Vec<(Txid, BlockId)> {
        self._history_txids(b'I', &asset_id.into_inner()[..], limit)
    }
}
