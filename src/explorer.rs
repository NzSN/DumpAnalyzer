//! Catalog-backed dump browsing, independent of the analysis work queue.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::sync::Mutex;
use tokio::task::JoinSet;

use crate::client::LedgerClient;
use crate::state::Store;
use crate::types::{AnalyzerError, JobIdentity, JobPhase, Result};
use crate::wire::{DumpCatalogEntry, DumpCatalogQuery, DumpPhase};

const CATALOG_CACHE_DURATION: Duration = Duration::from_secs(30);
const METADATA_CONCURRENCY: usize = 8;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExplorerSnapshot {
    pub total: usize,
    pub customers: Vec<ExplorerCustomer>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExplorerCustomer {
    pub customer_id: String,
    pub display_name: String,
    pub dump_count: usize,
    pub cases: Vec<ExplorerCase>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExplorerCase {
    pub case_id: String,
    pub title: String,
    pub dump_count: usize,
    pub dumps: Vec<ExplorerDump>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExplorerDump {
    pub dump_id: String,
    pub original_name: String,
    pub byte_size: Option<String>,
    pub sha256: Option<String>,
    pub received_at: String,
    pub analysis_phase: Option<JobPhase>,
}

struct CachedCatalog {
    fetched_at: Instant,
    snapshot: ExplorerSnapshot,
}

/// Reads all available dumps from DumpLedger, including settled analyses.
/// Remote metadata is shared across requests for 30 seconds; local analysis
/// phases are read afresh so an in-progress analysis never waits for the cache.
pub struct DumpsExplorer {
    client: Arc<LedgerClient>,
    store: Store,
    analyzer_version: String,
    cache: Mutex<Option<CachedCatalog>>,
}

impl DumpsExplorer {
    pub fn new(client: Arc<LedgerClient>, store: Store, analyzer_version: String) -> Self {
        Self {
            client,
            store,
            analyzer_version,
            cache: Mutex::new(None),
        }
    }

    pub async fn snapshot(&self) -> Result<ExplorerSnapshot> {
        // Serialize refreshes, including the first request, rather than sending
        // one catalog traversal for every dashboard request arriving together.
        let mut guard = self.cache.lock().await;
        let fresh = guard
            .as_ref()
            .is_some_and(|cache| cache.fetched_at.elapsed() < CATALOG_CACHE_DURATION);
        let mut snapshot = if fresh {
            guard.as_ref().expect("fresh cache exists").snapshot.clone()
        } else {
            let snapshot = self.load_catalog().await?;
            *guard = Some(CachedCatalog {
                fetched_at: Instant::now(),
                snapshot: snapshot.clone(),
            });
            snapshot
        };
        drop(guard);

        let jobs = self.store.jobs();
        for customer in &mut snapshot.customers {
            for case in &mut customer.cases {
                for dump in &mut case.dumps {
                    if let Some(sha256) = &dump.sha256 {
                        dump.analysis_phase = jobs.phase_of(&JobIdentity {
                            dump_id: dump.dump_id.clone(),
                            input_sha256: sha256.clone(),
                            kind: "triage".to_owned(),
                            analyzer_version: self.analyzer_version.clone(),
                        })?;
                    }
                }
            }
        }
        Ok(snapshot)
    }

    async fn load_catalog(&self) -> Result<ExplorerSnapshot> {
        let query = DumpCatalogQuery {
            phase: Some(DumpPhase::Available),
            ..DumpCatalogQuery::default()
        };
        let mut cursor = None;
        let mut cursors = BTreeSet::new();
        let mut entries = BTreeMap::new();
        loop {
            let page = self.client.get_dumps(&query, cursor.as_deref()).await?;
            for dump in page.dumps {
                entries.insert(dump.dump_id.clone(), dump);
            }
            match page.next_cursor {
                None => break,
                Some(next) if cursors.insert(next.clone()) => cursor = Some(next),
                Some(_) => {
                    return Err(AnalyzerError::Decode(
                        "dump explorer catalog repeated a pagination cursor".to_owned(),
                    ));
                }
            }
        }
        if entries.is_empty() {
            return Ok(ExplorerSnapshot {
                total: 0,
                customers: Vec::new(),
            });
        }

        let names = match self.client.list_customers().await {
            Ok(customers) => customers
                .into_iter()
                .map(|customer| (customer.customer_id, customer.display_name))
                .collect::<BTreeMap<_, _>>(),
            Err(error) if metadata_route_absent(&error) => BTreeMap::new(),
            Err(error) => return Err(error),
        };
        let titles = self.case_titles(entries.values()).await?;
        Ok(group_catalog(entries.into_values(), &names, &titles))
    }

    async fn case_titles<'a>(
        &self,
        entries: impl Iterator<Item = &'a DumpCatalogEntry>,
    ) -> Result<BTreeMap<String, String>> {
        let representatives: BTreeMap<_, _> = entries
            .map(|dump| (dump.case_id.clone(), dump.dump_id.clone()))
            .collect();
        let mut pending = representatives.into_iter();
        let mut tasks = JoinSet::new();
        let mut titles = BTreeMap::new();
        loop {
            while tasks.len() < METADATA_CONCURRENCY {
                let Some((case_id, dump_id)) = pending.next() else {
                    break;
                };
                let client = Arc::clone(&self.client);
                tasks.spawn(async move {
                    let detail = client.get_dump(&dump_id).await;
                    (case_id, dump_id, detail)
                });
            }
            let Some(result) = tasks.join_next().await else {
                break;
            };
            let (case_id, dump_id, detail) = result.map_err(|error| {
                AnalyzerError::State(format!("dump explorer metadata task failed: {error}"))
            })?;
            match detail {
                Ok(detail) if detail.dump_id == dump_id && detail.case_ref.case_id == case_id => {
                    titles.insert(case_id, detail.case_ref.title);
                }
                Ok(_) => {
                    return Err(AnalyzerError::Decode(
                        "dump explorer detail identity differs from its catalog entry".to_owned(),
                    ));
                }
                Err(error) if metadata_route_absent(&error) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(titles)
    }
}

fn metadata_route_absent(error: &AnalyzerError) -> bool {
    matches!(
        error,
        AnalyzerError::Server {
            status: 404 | 405 | 501,
            ..
        }
    )
}

fn group_catalog(
    entries: impl Iterator<Item = DumpCatalogEntry>,
    names: &BTreeMap<String, String>,
    titles: &BTreeMap<String, String>,
) -> ExplorerSnapshot {
    let mut groups: BTreeMap<String, BTreeMap<String, Vec<ExplorerDump>>> = BTreeMap::new();
    let mut total = 0;
    for entry in entries {
        groups
            .entry(entry.customer_id)
            .or_default()
            .entry(entry.case_id)
            .or_default()
            .push(ExplorerDump {
                dump_id: entry.dump_id,
                original_name: entry.original_name,
                byte_size: entry.byte_size,
                sha256: entry.sha256,
                received_at: entry.received_at,
                analysis_phase: None,
            });
        total += 1;
    }
    let mut customers = Vec::with_capacity(groups.len());
    for (customer_id, groups) in groups {
        let mut cases = Vec::with_capacity(groups.len());
        for (case_id, mut dumps) in groups {
            dumps.sort_by(|left, right| {
                right
                    .received_at
                    .cmp(&left.received_at)
                    .then_with(|| left.dump_id.cmp(&right.dump_id))
            });
            cases.push(ExplorerCase {
                title: titles
                    .get(&case_id)
                    .cloned()
                    .unwrap_or_else(|| case_id.clone()),
                case_id,
                dump_count: dumps.len(),
                dumps,
            });
        }
        cases.sort_by(|left, right| {
            left.title
                .cmp(&right.title)
                .then_with(|| left.case_id.cmp(&right.case_id))
        });
        customers.push(ExplorerCustomer {
            display_name: names
                .get(&customer_id)
                .cloned()
                .unwrap_or_else(|| customer_id.clone()),
            customer_id,
            dump_count: cases.iter().map(|case| case.dump_count).sum(),
            cases,
        });
    }
    customers.sort_by(|left, right| {
        left.display_name
            .cmp(&right.display_name)
            .then_with(|| left.customer_id.cmp(&right.customer_id))
    });
    ExplorerSnapshot { total, customers }
}
