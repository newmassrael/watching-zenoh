// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A minimal, hand-rolled HTTP/1.1 request reader + response writer — ZERO
//! external HTTP dependency, scoped to the trusted-localhost REST bridge.
//!
//! Deliberately-omitted features (documented, not silently mis-handled):
//! keep-alive (`Connection: close` per request), HTTP/2, TLS, pipelining, and
//! `Transfer-Encoding: chunked` (a `chunked` request is rejected `501`, not
//! silently mis-parsed). Absent `Content-Length` on a body method is treated as
//! an empty body per RFC 7230 3.3.3 rule 6 (NOT `411`) so a body-less `DELETE`
//! or empty `PUT` works. Sizes are bounded ([`MAX_HEAD_BYTES`]/[`MAX_BODY_BYTES`])
//! and the per-connection read is time-bounded by the caller so a stalled or
//! hostile local client cannot pin a task + fd forever.

use std::collections::BTreeMap;

use tokio::io::{AsyncRead, AsyncReadExt};

/// Cap on the request line + header block. Exceeding it -> `431`.
pub const MAX_HEAD_BYTES: usize = 8 * 1024;
/// Cap on the request body (`Content-Length`). Exceeding it -> `413`.
pub const MAX_BODY_BYTES: u64 = 8 * 1024 * 1024;

/// The HTTP methods the bridge understands. An unknown method is rejected
/// `405` at parse time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
    Put,
    Patch,
    Delete,
    Options,
    Head,
}

/// A parsed request: method, raw request-target (`path` + optional `?query`),
/// lower-cased headers, and the (bounded) body.
pub struct Request {
    pub method: Method,
    pub target: String,
    pub headers: Headers,
    pub body: Vec<u8>,
}

/// Case-insensitive header map (keys stored lower-cased).
pub struct Headers(BTreeMap<String, String>);

impl Headers {
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0.get(name).map(String::as_str)
    }
}

/// Outcome of a failed read.
pub enum ParseError {
    /// The peer closed cleanly before sending any request byte — nothing to
    /// answer, just drop the connection.
    Empty,
    /// A malformed request mapped to an HTTP status (code, reason phrase).
    Status(u16, &'static str),
}

#[inline]
fn bad(code: u16, reason: &'static str) -> ParseError {
    ParseError::Status(code, reason)
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Read and parse exactly one HTTP/1.1 request from `rd`. The caller is
/// responsible for wrapping this in a timeout (a stalled client never
/// completing the head/body would otherwise block here indefinitely).
pub async fn read_request<R: AsyncRead + Unpin>(rd: &mut R) -> Result<Request, ParseError> {
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut tmp = [0u8; 4096];

    // Phase 1: read until the CRLFCRLF head terminator, bounded.
    let head_end = loop {
        if let Some(pos) = find_double_crlf(&buf) {
            break pos;
        }
        if buf.len() > MAX_HEAD_BYTES {
            return Err(bad(431, "Request Header Fields Too Large"));
        }
        let n = rd
            .read(&mut tmp)
            .await
            .map_err(|_| bad(400, "Bad Request"))?;
        if n == 0 {
            // EOF: clean pre-request close vs a truncated head.
            return Err(if buf.is_empty() {
                ParseError::Empty
            } else {
                bad(400, "Bad Request")
            });
        }
        buf.extend_from_slice(&tmp[..n]);
    };

    let head = &buf[..head_end];
    // Reject embedded NULs / non-UTF-8 in the head outright.
    if head.contains(&0) {
        return Err(bad(400, "Bad Request"));
    }
    let head_str = std::str::from_utf8(head).map_err(|_| bad(400, "Bad Request"))?;

    let mut lines = head_str.split("\r\n");
    let request_line = lines.next().ok_or_else(|| bad(400, "Bad Request"))?;
    let (method, target) = parse_request_line(request_line)?;

    let mut headers: BTreeMap<String, String> = BTreeMap::new();
    let mut content_length: Option<u64> = None;
    let mut has_transfer_encoding = false;

    for line in lines {
        if line.is_empty() {
            continue;
        }
        // Obsolete line folding (a header line starting with whitespace) is
        // rejected (RFC 7230 3.2.4).
        if line.starts_with(' ') || line.starts_with('\t') {
            return Err(bad(400, "Bad Request"));
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| bad(400, "Bad Request"))?;
        // A space before the colon (`Name : v`) is illegal; `split_once` keeps
        // the space in `name`, so a whitespace-containing name is rejected.
        if name.is_empty() || name.chars().any(char::is_whitespace) {
            return Err(bad(400, "Bad Request"));
        }
        let name = name.to_ascii_lowercase();
        let value = value.trim().to_string();

        if name == "content-length" {
            let n: u64 = value.parse().map_err(|_| bad(400, "Bad Request"))?;
            match content_length {
                // Conflicting duplicate Content-Length is a smuggling vector.
                Some(prev) if prev != n => return Err(bad(400, "Bad Request")),
                _ => content_length = Some(n),
            }
        } else if name == "transfer-encoding" {
            has_transfer_encoding = true;
        }
        headers.insert(name, value);
    }

    // Transfer-Encoding is unsupported (chunked etc.); combined with
    // Content-Length it is a smuggling vector -> 400, else 501.
    if has_transfer_encoding {
        return Err(if content_length.is_some() {
            bad(400, "Bad Request")
        } else {
            bad(501, "Not Implemented")
        });
    }

    // Absent Content-Length == empty body (RFC 7230 3.3.3 rule 6), NOT 411.
    let body_len = content_length.unwrap_or(0);
    if body_len > MAX_BODY_BYTES {
        return Err(bad(413, "Payload Too Large"));
    }
    let body_len = body_len as usize;

    // Phase 2: the body — the bytes already buffered past the head terminator,
    // then read the remainder (bounded by body_len).
    let mut body = buf[head_end + 4..].to_vec();
    body.truncate(body_len); // discard any pipelined extra (we close anyway)
    while body.len() < body_len {
        let n = rd
            .read(&mut tmp)
            .await
            .map_err(|_| bad(400, "Bad Request"))?;
        if n == 0 {
            // Client closed before delivering the declared body.
            return Err(bad(400, "Bad Request"));
        }
        let need = body_len - body.len();
        body.extend_from_slice(&tmp[..n.min(need)]);
    }

    Ok(Request {
        method,
        target,
        headers: Headers(headers),
        body,
    })
}

fn parse_request_line(line: &str) -> Result<(Method, String), ParseError> {
    let mut it = line.split(' ');
    let method = it.next().ok_or_else(|| bad(400, "Bad Request"))?;
    let target = it.next().ok_or_else(|| bad(400, "Bad Request"))?;
    let version = it.next().ok_or_else(|| bad(400, "Bad Request"))?;
    if it.next().is_some() {
        return Err(bad(400, "Bad Request"));
    }
    if !version.starts_with("HTTP/1.") {
        return Err(bad(505, "HTTP Version Not Supported"));
    }
    if target.is_empty() {
        return Err(bad(400, "Bad Request"));
    }
    let method = match method {
        "GET" => Method::Get,
        "POST" => Method::Post,
        "PUT" => Method::Put,
        "PATCH" => Method::Patch,
        "DELETE" => Method::Delete,
        "OPTIONS" => Method::Options,
        "HEAD" => Method::Head,
        _ => return Err(bad(405, "Method Not Allowed")),
    };
    Ok((method, target.to_string()))
}

/// An HTTP response: status + reason, a content-type (empty = omit the header,
/// e.g. a `204`), and the body.
pub struct Response {
    pub status: u16,
    pub reason: &'static str,
    pub content_type: String,
    pub body: Vec<u8>,
}

impl Response {
    pub fn json(body: Vec<u8>) -> Self {
        Self {
            status: 200,
            reason: "OK",
            content_type: "application/json".to_string(),
            body,
        }
    }

    pub fn text(status: u16, reason: &'static str, msg: &str) -> Self {
        Self {
            status,
            reason,
            content_type: "text/plain; charset=utf-8".to_string(),
            body: msg.as_bytes().to_vec(),
        }
    }

    pub fn empty(status: u16, reason: &'static str) -> Self {
        Self {
            status,
            reason,
            content_type: "text/plain; charset=utf-8".to_string(),
            body: Vec::new(),
        }
    }

    /// A raw single-value response carrying the sample's own encoding as the
    /// content-type (the `?_raw` GET path).
    pub fn raw(content_type: String, body: Vec<u8>) -> Self {
        Self {
            status: 200,
            reason: "OK",
            content_type,
            body,
        }
    }

    /// CORS preflight answer: `204` + the allowed methods (emitted on every
    /// response below), no body.
    pub fn options() -> Self {
        Self {
            status: 204,
            reason: "No Content",
            content_type: String::new(),
            body: Vec::new(),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(160 + self.body.len());
        out.extend_from_slice(format!("HTTP/1.1 {} {}\r\n", self.status, self.reason).as_bytes());
        if !self.content_type.is_empty() {
            out.extend_from_slice(format!("Content-Type: {}\r\n", self.content_type).as_bytes());
        }
        // A 204 carries no body and must omit Content-Length (RFC 7230 3.3.2).
        if self.status != 204 {
            out.extend_from_slice(format!("Content-Length: {}\r\n", self.body.len()).as_bytes());
        }
        out.extend_from_slice(b"Access-Control-Allow-Origin: *\r\n");
        out.extend_from_slice(
            b"Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS\r\n",
        );
        out.extend_from_slice(b"Access-Control-Allow-Headers: Content-Type\r\n");
        out.extend_from_slice(b"Connection: close\r\n\r\n");
        out.extend_from_slice(&self.body);
        out
    }
}
