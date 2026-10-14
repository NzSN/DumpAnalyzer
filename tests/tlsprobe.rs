//! Live TLS probe (field-run diagnostics). Ignored by default; run with:
//! PROBE_URL=https://192.168.150.219:4080/health PROBE_CA=/tmp/da-field/proxy-cert.pem \
//!   cargo test --test tlsprobe -- --ignored --nocapture

#[test]
#[ignore = "live probe only"]
fn probe() {
    let url = std::env::var("PROBE_URL").expect("PROBE_URL");
    let ca = std::env::var("PROBE_CA").expect("PROBE_CA");
    let pem = std::fs::read(ca).expect("read ca");
    let certs = reqwest::Certificate::from_pem_bundle(&pem).expect("bundle");
    let mut builder = reqwest::Client::builder();
    for cert in certs {
        builder = builder.add_root_certificate(cert);
    }
    let client = builder.build().expect("client");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("rt");
    rt.block_on(async {
        match client.get(&url).send().await {
            Ok(resp) => println!("PROBE OK: {}", resp.status()),
            Err(err) => {
                println!("PROBE ERROR: {err}");
                let mut source = std::error::Error::source(&err);
                while let Some(cause) = source {
                    println!("  caused by: {cause}");
                    source = std::error::Error::source(cause);
                }
            }
        }
    });
}
