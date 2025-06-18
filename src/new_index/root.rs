struct IndexerConfig {
    light_mode: bool,
    address_search: bool,
    index_unspendables: bool,
    network: Network,
    allow_missing: bool,
    start_height: usize,
    stop_height: usize,
    #[cfg(feature = "liquid")]
    parent_network: crate::chain::BNetwork,
}

impl From<&Config> for IndexerConfig {
    fn from(config: &Config) -> Self {
        IndexerConfig {
            light_mode: config.light_mode,
            address_search: config.address_search,
            index_unspendables: config.index_unspendables,
            network: config.network_type,
            allow_missing: config.allow_missing,
            start_height: config.start_height,
            stop_height: config.stop_height,
            #[cfg(feature = "liquid")]
            parent_network: config.parent_network,
        }
    }
}

pub struct Indexer {
    store: Arc<Store>,
    flush: DBFlush,
    from: FetchFrom,
    iconfig: IndexerConfig,
    vault_indexer: vault::VaultIndexer,
    duration: HistogramVec,
    tip_metric: Gauge,
}

// TODO: &[Block] should be an iterator / a queue.
impl Indexer {
    pub fn open(store: Arc<Store>, from: FetchFrom, config: &Config, metrics: &Metrics) -> Self {
        let vault_indexer = vault::VaultIndexer::new(
            config.network_type,
            config.vault_tag.clone(),
            config.vault_version,
            store.clone(),
        );
        Indexer {
            store,
            flush: DBFlush::Disable,
            from,
            iconfig: IndexerConfig::from(config),
            vault_indexer,
            duration: metrics.histogram_vec(
                HistogramOpts::new("index_duration", "Index update duration (in seconds)"),
                &["step"],
            ),
            tip_metric: metrics.gauge(MetricOpts::new("tip_height", "Current chain tip height")),
        }
    }

    fn start_timer(&self, name: &str) -> HistogramTimer {
        self.duration.with_label_values(&[name]).start_timer()
    }

    fn headers_to_add(&self, new_headers: &[HeaderEntry]) -> Vec<HeaderEntry> {
        let added_blockhashes = self.store.added_blockhashes.read().unwrap();
        let headers_to_add = new_headers
            .iter()
            .filter(|e| {
                !added_blockhashes.contains(e.hash())
                    && e.height() >= self.iconfig.start_height
                    && e.height() <= self.iconfig.stop_height
            })
            .cloned()
            .collect();

        headers_to_add
    }

    fn headers_to_index(&self, new_headers: &[HeaderEntry]) -> Vec<HeaderEntry> {
        let indexed_blockhashes = self.store.indexed_blockhashes.read().unwrap();
        new_headers
            .iter()
            .filter(|e| !indexed_blockhashes.contains(e.hash()))
            .cloned()
            .collect()
    }

    fn start_auto_compactions(&self, db: &DB) {
        let key = b"F".to_vec();
        if db.get(&key).is_none() {
            db.full_compaction();
            db.put_sync(&key, b"");
            assert!(db.get(&key).is_some());
        }
        db.enable_auto_compaction();
    }

    fn get_new_headers(&self, daemon: &Daemon, tip: &BlockHash) -> Result<Vec<HeaderEntry>> {
        let headers = self.store.indexed_headers.read().unwrap();
        let new_headers = daemon.get_new_headers(&headers, tip)?;
        let result = headers.order(new_headers);

        if let Some(tip) = result.last() {
            info!("{:?} ({} left to index)", tip, result.len());
        };
        Ok(result)
    }

    pub fn update(&mut self, daemon: &Daemon) -> Result<BlockHash> {
        let daemon = daemon.reconnect()?;
        let tip = daemon.getbestblockhash()?;
        let new_headers = self.get_new_headers(&daemon, &tip)?;

        let to_add = self.headers_to_add(&new_headers);
        debug!(
            "adding transactions from {} blocks using {:?}",
            to_add.len(),
            self.from
        );
        start_fetcher(self.from, &daemon, to_add)?.map(|blocks| self.add(&blocks));
        self.start_auto_compactions(&self.store.txstore_db);

        let to_index = self.headers_to_index(&new_headers);
        debug!(
            "indexing history from {} blocks using {:?}",
            to_index.len(),
            self.from
        );
        let blocks = start_fetcher(self.from, &daemon, to_index)?;
        blocks.map(|blocks| self.index(&blocks));
        self.start_auto_compactions(&self.store.history_db);

        if let DBFlush::Disable = self.flush {
            debug!("flushing to disk");
            self.store.txstore_db.flush();
            self.store.history_db.flush();
            self.flush = DBFlush::Enable;
        }

        // update the synced tip *after* the new data is flushed to disk
        debug!("updating synced tip to {:?}", tip);
        self.store.txstore_db.put_sync(b"t", &serialize(&tip));

        let mut headers = self.store.indexed_headers.write().unwrap();
        headers.apply(new_headers);
        assert_eq!(tip, *headers.tip());

        if let FetchFrom::BlkFiles = self.from {
            self.from = FetchFrom::Bitcoind;
        }

        self.tip_metric.set(headers.len() as i64 - 1);

        Ok(tip)
    }

    fn add(&self, blocks: &[BlockEntry]) {
        debug!("Adding {} blocks to Indexer", blocks.len());
        // TODO: skip orphaned blocks?
        let rows = {
            let _timer = self.start_timer("add_process");
            add_blocks(blocks, &self.iconfig)
        };
        {
            let _timer = self.start_timer("add_write");
            self.store.txstore_db.write(rows, self.flush);
        }

        self.store
            .added_blockhashes
            .write()
            .unwrap()
            .extend(blocks.iter().map(|b| {
                if b.entry.height() % 10_000 == 0 {
                    info!("Tx indexing is up to height={}", b.entry.height());
                }
                b.entry.hash()
            }));
    }

    fn index(&self, blocks: &[BlockEntry]) {
        debug!(
            "Indexing {} blocks from {} with Indexer",
            blocks.len(),
            blocks[0].entry.height()
        );
        let previous_txos_map = {
            let _timer = self.start_timer("index_lookup");
            lookup_txos(
                &self.store.txstore_db,
                &get_previous_txos(blocks),
                self.iconfig.allow_missing,
            )
        };
        let history_rows = {
            let _timer = self.start_timer("index_process");
            let added_blockhashes = self.store.added_blockhashes.read().unwrap();
            for b in blocks {
                if b.entry.height() % 10_000 == 0 {
                    info!("History indexing is up to height={}", b.entry.height());
                }
                let blockhash = b.entry.hash();
                // TODO: replace by lookup into txstore_db?
                if !added_blockhashes.contains(blockhash) {
                    panic!("cannot index block {} (missing from store)", blockhash);
                }
            }
            //Index and store vault txs in second phase
            //The first phase populates the txstore database,
            // the second phase populates the history database and vault store.
            self.vault_indexer.index_blocks(blocks);
            index_blocks(blocks, &previous_txos_map, &self.iconfig)
        };
        self.store.history_db.write(history_rows, self.flush);
    }
}

fn add_blocks(block_entries: &[BlockEntry], iconfig: &IndexerConfig) -> Vec<DBRow> {
    // persist individual transactions:
    //      T{txid} → {rawtx}
    //      C{txid}{blockhash}{height} →
    //      O{txid}{index} → {txout}
    // persist block headers', block txids' and metadata rows:
    //      B{blockhash} → {header}
    //      X{blockhash} → {txid1}...{txidN}
    //      M{blockhash} → {tx_count}{size}{weight}
    block_entries
        .par_iter() // serialization is CPU-intensive
        .map(|b| {
            let mut rows = vec![];
            let blockhash = full_hash(&b.entry.hash()[..]);
            let txids: Vec<Txid> = b.block.txdata.iter().map(|tx| tx.compute_txid()).collect();
            for tx in &b.block.txdata {
                add_transaction(tx, blockhash, &mut rows, iconfig);
            }

            if !iconfig.light_mode {
                rows.push(BlockRow::new_txids(blockhash, &txids).into_row());
                rows.push(BlockRow::new_meta(blockhash, &BlockMeta::from(b)).into_row());
            }

            rows.push(BlockRow::new_header(b).into_row());
            rows.push(BlockRow::new_done(blockhash).into_row()); // mark block as "added"
            rows
        })
        .flatten()
        .collect()
}

fn add_transaction(
    tx: &Transaction,
    blockhash: FullHash,
    rows: &mut Vec<DBRow>,
    iconfig: &IndexerConfig,
) {
    rows.push(TxConfRow::new(tx, blockhash).into_row());

    if !iconfig.light_mode {
        rows.push(TxRow::new(tx).into_row());
    }

    let txid = full_hash(&tx.compute_txid()[..]);
    for (txo_index, txo) in tx.output.iter().enumerate() {
        if is_spendable(txo) {
            rows.push(TxOutRow::new(&txid, txo_index, txo).into_row());
        }
    }
}

fn get_previous_txos(block_entries: &[BlockEntry]) -> BTreeSet<OutPoint> {
    block_entries
        .iter()
        .flat_map(|b| b.block.txdata.iter())
        .flat_map(|tx| {
            tx.input
                .iter()
                .filter(|txin| has_prevout(txin))
                .map(|txin| txin.previous_output)
        })
        .collect()
}

fn lookup_txos(
    txstore_db: &DB,
    outpoints: &BTreeSet<OutPoint>,
    allow_missing: bool,
) -> HashMap<OutPoint, TxOut> {
    let mut loop_count = 10;
    let pool = loop {
        match rayon::ThreadPoolBuilder::new()
            .num_threads(16) // we need to saturate SSD IOPS
            .thread_name(|i| format!("lookup-txo-{}", i))
            .build()
        {
            Ok(pool) => break pool,
            Err(e) => {
                if loop_count == 0 && !allow_missing {
                    panic!("schema::lookup_txos failed to create a ThreadPool: {}", e);
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
                loop_count -= 1;
            }
        }
    };
    pool.install(|| {
        outpoints
            .par_iter()
            .filter_map(|outpoint| {
                lookup_txo(txstore_db, outpoint)
                    .or_else(|| {
                        if !allow_missing {
                            panic!("missing txo {} in {:?}", outpoint, txstore_db);
                        }
                        None
                    })
                    .map(|txo| (*outpoint, txo))
            })
            .collect()
    })
}

pub(super) fn lookup_txo(txstore_db: &DB, outpoint: &OutPoint) -> Option<TxOut> {
    txstore_db
        .get(&TxOutRow::key(outpoint))
        .map(|val| deserialize(&val).expect("failed to parse TxOut"))
}

fn index_blocks(
    block_entries: &[BlockEntry],
    previous_txos_map: &HashMap<OutPoint, TxOut>,
    iconfig: &IndexerConfig,
) -> Vec<DBRow> {
    block_entries
        .par_iter() // serialization is CPU-intensive
        .map(|b| {
            let mut rows = vec![];
            for (idx, tx) in b.block.txdata.iter().enumerate() {
                let height = b.entry.height() as u32;
                index_transaction(
                    tx,
                    height,
                    idx as u16,
                    previous_txos_map,
                    &mut rows,
                    iconfig,
                );
            }
            rows.push(BlockRow::new_done(full_hash(&b.entry.hash()[..])).into_row()); // mark block as "indexed"
            rows
        })
        .flatten()
        .collect()
}

// TODO: return an iterator?
fn index_transaction(
    tx: &Transaction,
    confirmed_height: u32,
    tx_position: u16,
    previous_txos_map: &HashMap<OutPoint, TxOut>,
    rows: &mut Vec<DBRow>,
    iconfig: &IndexerConfig,
) {
    // persist history index:
    //      H{funding-scripthash}{spending-height}{spending-block-pos}S{spending-txid:vin}{funding-txid:vout} → ""
    //      H{funding-scripthash}{funding-height}{funding-block-pos}F{funding-txid:vout} → ""
    // persist "edges" for fast is-this-TXO-spent check
    //      S{funding-txid:vout}{spending-txid:vin} → ""
    let txid = full_hash(&tx.compute_txid()[..]);
    for (txo_index, txo) in tx.output.iter().enumerate() {
        if is_spendable(txo) || iconfig.index_unspendables {
            let history = TxHistoryRow::new(
                &txo.script_pubkey,
                confirmed_height,
                tx_position,
                TxHistoryInfo::Funding(FundingInfo {
                    txid,
                    vout: txo_index as u32,
                    value: txo.value.to_sat(),
                }),
            );
            rows.push(history.into_row());

            if iconfig.address_search {
                if let Some(row) = addr_search_row(&txo.script_pubkey, iconfig.network) {
                    rows.push(row);
                }
            }
        }
    }
    for (txi_index, txi) in tx.input.iter().enumerate() {
        if !has_prevout(txi) {
            continue;
        }
        let prev_txo = previous_txos_map.get(&txi.previous_output);

        if prev_txo.is_none() && !iconfig.allow_missing {
            panic!("missing previous txo {}", txi.previous_output);
        };

        let empty_script = ScriptBuf::new();
        let history = TxHistoryRow::new(
            prev_txo.map_or(&empty_script, |txo| &txo.script_pubkey),
            confirmed_height,
            tx_position,
            TxHistoryInfo::Spending(SpendingInfo {
                txid,
                vin: txi_index as u32,
                prev_txid: full_hash(&txi.previous_output.txid[..]),
                prev_vout: txi.previous_output.vout,
                value: prev_txo.map_or(Value::default(), |txo| txo.value.to_sat()),
            }),
        );
        rows.push(history.into_row());

        let edge = TxEdgeRow::new(
            full_hash(&txi.previous_output.txid[..]),
            txi.previous_output.vout,
            txid,
            txi_index as u32,
        );
        rows.push(edge.into_row());
    }

    // Index issued assets & native asset pegins/pegouts/burns
    #[cfg(feature = "liquid")]
    asset::index_confirmed_tx_assets(
        tx,
        confirmed_height,
        tx_position,
        iconfig.network,
        iconfig.parent_network,
        rows,
    );
}

fn addr_search_row(spk: &ScriptBuf, network: Network) -> Option<DBRow> {
    spk.to_address_str(network).map(|address| DBRow {
        key: [b"a", address.as_bytes()].concat(),
        value: vec![],
    })
}

fn addr_search_filter(prefix: &str) -> Bytes {
    [b"a", prefix.as_bytes()].concat()
}
