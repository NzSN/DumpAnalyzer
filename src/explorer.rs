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

#[derive(Debug, Clone)]
pub struct BrowseQuery {
    pub customer_id: Option<String>,
    pub case_id: Option<String>,
    pub q: String,
    pub page: usize,
    pub page_size: usize,
}

impl Default for BrowseQuery {
    fn default() -> Self {
        Self {
            customer_id: None,
            case_id: None,
            q: String::new(),
            page: 1,
            page_size: 25,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowseCustomer {
    pub customer_id: String,
    pub display_name: String,
    pub case_count: usize,
    pub dump_count: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowseCase {
    pub case_id: String,
    pub title: String,
    pub dump_count: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomerScope {
    pub customer_id: String,
    pub display_name: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaseScope {
    pub case_id: String,
    pub title: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowsePage {
    pub level: &'static str,
    pub total: usize,
    pub scope_dump_count: usize,
    pub matching: usize,
    pub page: usize,
    pub page_size: usize,
    pub total_pages: usize,
    pub customer: Option<CustomerScope>,
    #[serde(rename = "case")]
    pub case_ref: Option<CaseScope>,
    pub customers: Vec<BrowseCustomer>,
    pub cases: Vec<BrowseCase>,
    pub dumps: Vec<ExplorerDump>,
}

struct CachedCatalog {
    fetched_at: Instant,
    snapshot: Arc<ExplorerSnapshot>,
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
        let catalog = self.catalog().await?;
        let mut snapshot = (*catalog).clone();
        for customer in &mut snapshot.customers {
            for case in &mut customer.cases {
                self.overlay_phases(&mut case.dumps)?;
            }
        }
        Ok(snapshot)
    }

    /// Return one hierarchy level with bounded rows. Cached descendants remain
    /// shared; only the requested page is cloned and enriched with local phase.
    pub async fn browse(&self, query: &BrowseQuery) -> Result<BrowsePage> {
        if query.page == 0
            || !(1..=100).contains(&query.page_size)
            || (query.case_id.is_some() && query.customer_id.is_none())
        {
            return Err(AnalyzerError::Server {
                status: 400,
                code: Some("invalid_query".to_owned()),
            });
        }
        let catalog = self.catalog().await?;
        let customer = query
            .customer_id
            .as_ref()
            .map(|id| {
                catalog
                    .customers
                    .iter()
                    .find(|customer| customer.customer_id == *id)
                    .ok_or_else(scope_not_found)
            })
            .transpose()?;
        let case = query
            .case_id
            .as_ref()
            .map(|id| {
                customer
                    .expect("case requires customer")
                    .cases
                    .iter()
                    .find(|case| case.case_id == *id)
                    .ok_or_else(scope_not_found)
            })
            .transpose()?;
        let needle = query.q.trim().to_lowercase();
        let customer_match =
            customer.is_some_and(|customer| customer_name_matches(customer, &needle));
        let case_match = case.is_some_and(|case| case_name_matches(case, &needle));
        let mut result = BrowsePage {
            level: if case.is_some() {
                "dumps"
            } else if customer.is_some() {
                "cases"
            } else {
                "customers"
            },
            total: catalog.total,
            scope_dump_count: case.map_or_else(
                || customer.map_or(catalog.total, |c| c.dump_count),
                |c| c.dump_count,
            ),
            matching: 0,
            page: 1,
            page_size: query.page_size,
            total_pages: 0,
            customer: customer.map(|customer| CustomerScope {
                customer_id: customer.customer_id.clone(),
                display_name: customer.display_name.clone(),
            }),
            case_ref: case.map(|case| CaseScope {
                case_id: case.case_id.clone(),
                title: case.title.clone(),
            }),
            customers: Vec::new(),
            cases: Vec::new(),
            dumps: Vec::new(),
        };
        if let Some(case) = case {
            let matches =
                |dump: &&ExplorerDump| customer_match || case_match || dump_matches(dump, &needle);
            result.set_page(case.dumps.iter().filter(matches).count(), query.page);
            result.dumps = case
                .dumps
                .iter()
                .filter(matches)
                .skip((result.page - 1) * query.page_size)
                .take(query.page_size)
                .cloned()
                .collect();
            self.overlay_phases(&mut result.dumps)?;
        } else if let Some(customer) = customer {
            let matches = |case: &&ExplorerCase| customer_match || case_matches(case, &needle);
            result.set_page(customer.cases.iter().filter(matches).count(), query.page);
            result.cases = customer
                .cases
                .iter()
                .filter(matches)
                .skip((result.page - 1) * query.page_size)
                .take(query.page_size)
                .map(|case| BrowseCase {
                    case_id: case.case_id.clone(),
                    title: case.title.clone(),
                    dump_count: case.dump_count,
                })
                .collect();
        } else {
            let matches = |customer: &&ExplorerCustomer| {
                customer_name_matches(customer, &needle)
                    || customer
                        .cases
                        .iter()
                        .any(|case| case_matches(case, &needle))
            };
            result.set_page(catalog.customers.iter().filter(matches).count(), query.page);
            result.customers = catalog
                .customers
                .iter()
                .filter(matches)
                .skip((result.page - 1) * query.page_size)
                .take(query.page_size)
                .map(|customer| BrowseCustomer {
                    customer_id: customer.customer_id.clone(),
                    display_name: customer.display_name.clone(),
                    case_count: customer.cases.len(),
                    dump_count: customer.dump_count,
                })
                .collect();
        }
        Ok(result)
    }

    async fn catalog(&self) -> Result<Arc<ExplorerSnapshot>> {
        // Serialize refreshes, including the first request, rather than sending
        // one catalog traversal for every dashboard request arriving together.
        let mut guard = self.cache.lock().await;
        let fresh = guard
            .as_ref()
            .is_some_and(|cache| cache.fetched_at.elapsed() < CATALOG_CACHE_DURATION);
        let snapshot = if fresh {
            Arc::clone(&guard.as_ref().expect("fresh cache exists").snapshot)
        } else {
            let snapshot = Arc::new(self.load_catalog().await?);
            *guard = Some(CachedCatalog {
                fetched_at: Instant::now(),
                snapshot: Arc::clone(&snapshot),
            });
            snapshot
        };
        Ok(snapshot)
    }

    fn overlay_phases(&self, dumps: &mut [ExplorerDump]) -> Result<()> {
        let jobs = self.store.jobs();
        for dump in dumps {
            if let Some(sha256) = &dump.sha256 {
                dump.analysis_phase = jobs.phase_of(&JobIdentity {
                    dump_id: dump.dump_id.clone(),
                    input_sha256: sha256.clone(),
                    kind: "triage".to_owned(),
                    analyzer_version: self.analyzer_version.clone(),
                })?;
            }
        }
        Ok(())
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

impl BrowsePage {
    fn set_page(&mut self, matching: usize, requested_page: usize) {
        self.matching = matching;
        self.total_pages = matching.div_ceil(self.page_size);
        self.page = requested_page.min(self.total_pages.max(1));
    }
}

fn scope_not_found() -> AnalyzerError {
    AnalyzerError::Server {
        status: 404,
        code: Some("scope_not_found".to_owned()),
    }
}

fn customer_name_matches(customer: &ExplorerCustomer, needle: &str) -> bool {
    customer.customer_id.to_lowercase().contains(needle)
        || customer.display_name.to_lowercase().contains(needle)
}

fn case_name_matches(case: &ExplorerCase, needle: &str) -> bool {
    case.case_id.to_lowercase().contains(needle) || case.title.to_lowercase().contains(needle)
}

fn dump_matches(dump: &ExplorerDump, needle: &str) -> bool {
    dump.dump_id.to_lowercase().contains(needle)
        || dump.original_name.to_lowercase().contains(needle)
}

fn case_matches(case: &ExplorerCase, needle: &str) -> bool {
    case_name_matches(case, needle) || case.dumps.iter().any(|dump| dump_matches(dump, needle))
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
