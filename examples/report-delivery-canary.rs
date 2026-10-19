//! Publish one already captured report to an explicitly selected test ledger.
//! Credentials come from the environment; no catalog scan or debugger execution.
use dump_analyzer::client::{LedgerClient, PostAnalysisResult};
use dump_analyzer::config::Config;
use dump_analyzer::report::CrashReportV2;
use dump_analyzer::state::{FullDelivery, ReportHandoff, Store};
use dump_analyzer::verdict;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments: Vec<String> = std::env::args().collect();
    if arguments.len() != 3 {
        return Err("usage: report-delivery-canary <canonical.json> <local-canary.sqlite>; set DUMP_ANALYZER_BASE_URL and TOKEN explicitly".into());
    }
    let report: CrashReportV2 = serde_json::from_slice(&std::fs::read(&arguments[1])?)?;
    report.validate()?;
    let mut config = Config::from_process_env()?;
    config.name = report.identity.analyzer_name.clone();
    config.version = report.identity.analyzer_version.clone();
    config.writeback_enabled = true;
    let store = Store::open(&arguments[2])?;
    let identity = report.identity.job();
    let compact = verdict::assemble(&identity, report.compact_output()?, &config)?;
    let stored = store
        .local_reports()
        .save_rich(&report, &compact, ReportHandoff::Manual, true)?;
    let client = LedgerClient::new(&config)?;
    verdict::submit(&client, &store, &identity, &compact).await?;
    assert_eq!(
        store.local_reports().get_rich(&identity)?.unwrap().delivery,
        FullDelivery::FullyDelivered
    );
    let acknowledgement = client.post_rich_analysis(&stored, &compact).await?;
    let PostAnalysisResult::Replayed(accepted) = acknowledgement else {
        return Err("second POST was not an idempotent replay".into());
    };
    let remote = client
        .get_rich_report(&identity.dump_id, &accepted.analysis_id)
        .await?;
    assert_eq!(remote.canonical_json()?, stored.report_json);
    assert_eq!(remote.digest()?, stored.digest);
    drop(store);
    let reopened = Store::open(&arguments[2])?;
    assert_eq!(
        reopened
            .local_reports()
            .get_rich(&identity)?
            .unwrap()
            .report,
        remote
    );
    println!(
        "{}",
        serde_json::json!({"analysisId":accepted.analysis_id,"reportId":report.report_id,"digest":stored.digest,"fullDelivery":"fullyDelivered","identicalRemoteDetail":true,"idempotentReplay":true,"localReopen":true})
    );
    Ok(())
}
