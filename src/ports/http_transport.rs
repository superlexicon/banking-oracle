//! Pluggable HTTP/TLS transport port (`ReqwestHttpTransport` for live HTTPS APIs + `MockHttpTransport`
//! for deterministic integration testing of bank & acquirer polling, OAuth2 token refresh, and RPC relay).

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{anyhow, Result};
use async_trait::async_trait;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
}

#[derive(Debug, Clone)]
pub struct OutboundHttpRequest {
    pub method: HttpMethod,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct OutboundHttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

impl OutboundHttpResponse {
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    pub fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T> {
        serde_json::from_slice(&self.body).map_err(|e| {
            anyhow!(
                "failed to decode HTTP JSON response (status {}): {} | raw={}",
                self.status,
                e,
                String::from_utf8_lossy(&self.body)
            )
        })
    }
}

#[async_trait]
pub trait HttpTransport: Send + Sync {
    async fn execute(&self, req: OutboundHttpRequest) -> Result<OutboundHttpResponse>;
}

/// Production HTTPS (`rustls-tls`) transport for calling CONNECT2OCBC, ISO 20022 gateways, Stripe, and L1 RPC.
pub struct ReqwestHttpTransport {
    client: reqwest::Client,
}

impl ReqwestHttpTransport {
    pub fn new(timeout_secs: u64) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .build()?;
        Ok(Self { client })
    }
}

#[async_trait]
impl HttpTransport for ReqwestHttpTransport {
    async fn execute(&self, req: OutboundHttpRequest) -> Result<OutboundHttpResponse> {
        let mut builder = match req.method {
            HttpMethod::Get => self.client.get(&req.url),
            HttpMethod::Post => self.client.post(&req.url),
        };
        for (k, v) in req.headers {
            builder = builder.header(k, v);
        }
        if !req.body.is_empty() {
            builder = builder.body(req.body);
        }
        let resp = builder.send().await?;
        let status = resp.status().as_u16();
        let body = resp.bytes().await?.to_vec();
        Ok(OutboundHttpResponse { status, body })
    }
}

/// Deterministic mock transport keyed by URL substring or exact URL for full sandbox/unit verification.
#[derive(Default)]
pub struct MockHttpTransport {
    routes: Mutex<HashMap<String, VecDeque<OutboundHttpResponse>>>,
    recorded_requests: Mutex<Vec<OutboundHttpRequest>>,
}

impl MockHttpTransport {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn enqueue_json(&self, url_pattern: &str, status: u16, payload: serde_json::Value) {
        let mut map = self.routes.lock().unwrap();
        map.entry(url_pattern.to_string())
            .or_default()
            .push_back(OutboundHttpResponse {
                status,
                body: serde_json::to_vec(&payload).unwrap(),
            });
    }

    pub fn recorded_requests(&self) -> Vec<OutboundHttpRequest> {
        self.recorded_requests.lock().unwrap().clone()
    }
}

#[async_trait]
impl HttpTransport for MockHttpTransport {
    async fn execute(&self, req: OutboundHttpRequest) -> Result<OutboundHttpResponse> {
        self.recorded_requests.lock().unwrap().push(req.clone());
        let mut map = self.routes.lock().unwrap();
        if let Some(q) = map.get_mut(&req.url) {
            if let Some(resp) = q.pop_front() {
                return Ok(resp);
            }
        }
        // Fallback: substring prefix/contains match for URLs with query parameters
        let matching_key = map
            .iter()
            .find(|(pat, q)| !q.is_empty() && req.url.contains(pat.as_str()))
            .map(|(k, _)| k.clone());
        if let Some(k) = matching_key {
            return Ok(map.get_mut(&k).unwrap().pop_front().unwrap());
        }
        Err(anyhow!("MockHttpTransport: no queued response matching URL '{}'", req.url))
    }
}
