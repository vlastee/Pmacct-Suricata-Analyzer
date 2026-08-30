//! HTTP client for the analyzer. Trust is exactly one root: the CA PEM captured at enrollment
//! (no system roots), so a spoofed server on the LAN cannot collect the token or feed data.
use crate::model::{EnrollRequest, EnrollResponse, EventsAck, EventsBatch};
use anyhow::{anyhow, bail, Context, Result};
use flate2::{write::GzEncoder, Compression};
use std::io::Write;
use std::time::Duration;

fn builder(ca_pem: Option<&str>, insecure: bool) -> Result<reqwest::ClientBuilder> {
    let mut b = reqwest::Client::builder()
        .use_rustls_tls()
        .timeout(Duration::from_secs(30))
        .user_agent(format!("pmacct-agent/{}", crate::VERSION));
    if let Some(pem) = ca_pem {
        let cert = reqwest::Certificate::from_pem(pem.as_bytes()).context("CA certificate")?;
        b = b.tls_built_in_root_certs(false).add_root_certificate(cert);
    }
    if insecure {
        b = b.danger_accept_invalid_certs(true);
    }
    Ok(b)
}

fn base(server: &str) -> String {
    server.trim().trim_end_matches('/').to_string()
}

async fn err_body(resp: reqwest::Response) -> anyhow::Error {
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    let msg = serde_json::from_str::<serde_json::Value>(&text)
        .ok()
        .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(String::from))
        .unwrap_or(text);
    anyhow!("http {}: {}", status.as_u16(), msg.trim())
}

/// Fetch the server's CA certificate without verifying TLS (first contact). The caller must
/// check its SPKI pin (or show the fingerprint for the operator to confirm) before trusting it.
pub async fn fetch_ca_insecure(server: &str) -> Result<String> {
    let http = builder(None, true)?.build()?;
    let resp = http.get(format!("{}/api/v1/tls/ca", base(server))).send().await.context("fetch CA")?;
    if !resp.status().is_success() {
        return Err(err_body(resp).await);
    }
    let pem = resp.text().await?;
    if !pem.contains("BEGIN CERTIFICATE") {
        bail!("server did not return a certificate");
    }
    Ok(pem)
}

/// Exchange an enrollment token for the agent's own token.
pub async fn enroll(server: &str, ca_pem: Option<&str>, req: &EnrollRequest) -> Result<EnrollResponse> {
    let http = builder(ca_pem, false)?.build()?;
    let resp = http.post(format!("{}/api/v1/agent/enroll", base(server))).json(req).send().await.context("enroll request")?;
    if !resp.status().is_success() {
        return Err(err_body(resp).await);
    }
    Ok(resp.json().await.context("enroll response")?)
}

pub struct Client {
    base: String,
    token: String,
    http: reqwest::Client,
}

impl Client {
    pub fn new(server: &str, token: &str, ca_pem: Option<&str>) -> Result<Self> {
        Ok(Self { base: base(server), token: token.to_string(), http: builder(ca_pem, false)?.build()? })
    }

    /// Upload one batch (gzip-compressed JSON).
    pub async fn send(&self, batch: &EventsBatch) -> Result<EventsAck> {
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(&serde_json::to_vec(batch)?)?;
        let body = gz.finish()?;
        let resp = self
            .http
            .post(format!("{}/api/v1/agent/events", self.base))
            .bearer_auth(&self.token)
            .header("Content-Type", "application/json")
            .header("Content-Encoding", "gzip")
            .body(body)
            .send()
            .await
            .context("send events")?;
        if !resp.status().is_success() {
            return Err(err_body(resp).await);
        }
        Ok(resp.json().await.context("events response")?)
    }
}
