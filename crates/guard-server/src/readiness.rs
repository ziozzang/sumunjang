//! Optional bounded, one-request HTTP probe listener; no policy/admin payloads.
use crate::App;
use std::{num::NonZeroUsize, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
const LIMIT: usize = 2048;
fn status(app: &App, header: &[u8]) -> u16 {
    let Ok(header) = std::str::from_utf8(header) else {
        return 400;
    };
    let mut lines = header.split("\r\n");
    let mut request = lines.next().unwrap_or("").split(' ');
    let (Some(method), Some(path), Some(version), None) = (
        request.next(),
        request.next(),
        request.next(),
        request.next(),
    ) else {
        return 400;
    };
    if !matches!(version, "HTTP/1.1" | "HTTP/1.0") {
        return 400;
    }
    let mut lengths = 0;
    let mut count = 0;
    for line in lines.take_while(|line| !line.is_empty()) {
        count += 1;
        if count > 16 {
            return 431;
        }
        let Some((name, value)) = line.split_once(':') else {
            return 400;
        };
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
            || !value.bytes().all(|b| b == b'\t' || (32..127).contains(&b))
        {
            return 400;
        }
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return 400;
        }
        if name.eq_ignore_ascii_case("content-length") {
            lengths += 1;
            if lengths > 1 || value.trim().parse::<u64>() != Ok(0) {
                return 400;
            }
        }
    }
    if method != "GET" {
        return 405;
    }
    match path {
        "/healthz" => 200,
        "/readyz" if app.ready_reason().is_none() => 200,
        "/readyz" => 503,
        _ => 404,
    }
}
async fn connection(mut io: tokio::net::TcpStream, app: App) {
    let work = async {
        let mut header = [0; LIMIT];
        let mut used = 0;
        let code = loop {
            if used == LIMIT {
                break 431;
            }
            let n = io.read(&mut header[used..]).await?;
            if n == 0 {
                return Ok::<(), std::io::Error>(());
            }
            used += n;
            if let Some(end) = header[..used].windows(4).position(|w| w == b"\r\n\r\n") {
                break status(&app, &header[..end + 4]);
            }
        };
        // Fixed status-only replies never echo paths, policy, state or credentials.
        let response=match code {
            200=>b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".as_slice(),
            503=>b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".as_slice(),
            404=>b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".as_slice(),
            405=>b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".as_slice(),
            431=>b"HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".as_slice(),
            _=>b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".as_slice(),
        };
        io.write_all(response).await?;
        io.shutdown().await
    };
    let _ = tokio::time::timeout(Duration::from_secs(1), work).await;
}
pub(crate) async fn serve(
    listener: tokio::net::TcpListener,
    app: App,
    mut stop: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    hangang_runtime::serve_connections(
        listener,
        NonZeroUsize::new(16).unwrap(),
        Duration::from_secs(1),
        move |io, _| connection(io, app.clone()),
        async move {
            if !*stop.borrow() {
                let _ = stop.changed().await;
            }
        },
    )
    .await?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn probe_has_only_exact_get_routes_and_refuses_bodies_or_ambiguous_framing() {
        let app = crate::tests::app();
        for (header, code) in [
            ("GET /healthz HTTP/1.1\r\n\r\n", 200),
            ("GET /readyz HTTP/1.1\r\n\r\n", 200),
            ("GET /v1/policy HTTP/1.1\r\n\r\n", 404),
            ("GET /readyz?detail=1 HTTP/1.1\r\n\r\n", 404),
            ("POST /readyz HTTP/1.1\r\n\r\n", 405),
            (
                "GET /readyz HTTP/1.1\r\nContent-Length: 100000000\r\n\r\n",
                400,
            ),
            (
                "GET /readyz HTTP/1.1\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
                400,
            ),
            (
                "GET /readyz HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
                400,
            ),
        ] {
            assert_eq!(status(&app, header.as_bytes()), code);
        }
    }
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn absent_source_probe_and_bounded_connection_shutdown() {
        let mut app = crate::tests::app();
        app.native_source = Some(crate::kubernetes_authority::Owner::new().unwrap());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(serve(listener, app, rx));
        let client = reqwest::Client::new();
        assert_eq!(
            client
                .get(format!("http://{address}/readyz"))
                .send()
                .await
                .unwrap()
                .status(),
            503
        );
        assert_eq!(
            client
                .get(format!("http://{address}/healthz"))
                .send()
                .await
                .unwrap()
                .status(),
            200
        );
        for (request, code) in [
            ("GET /v1/policy HTTP/1.1\r\n\r\n".to_owned(), "404"),
            (
                "GET /readyz HTTP/1.1\r\nContent-Length: 999999999\r\n\r\n".to_owned(),
                "400",
            ),
            (
                "GET /readyz HTTP/1.1\r\nBad Header: value\r\n\r\n".to_owned(),
                "400",
            ),
            (
                "GET /readyz HTTP/1.1\r\nX: ".to_owned() + &"x".repeat(2048),
                "431",
            ),
        ] {
            let mut io = tokio::net::TcpStream::connect(address).await.unwrap();
            io.write_all(request.as_bytes()).await.unwrap();
            let mut bytes = Vec::new();
            io.read_to_end(&mut bytes).await.unwrap();
            let reply = String::from_utf8(bytes).unwrap();
            assert!(reply.starts_with(&format!("HTTP/1.1 {code}")));
            assert!(reply.ends_with("Content-Length: 0\r\nConnection: close\r\n\r\n"));
        }
        let mut slow = tokio::net::TcpStream::connect(address).await.unwrap();
        slow.write_all(b"GET /readyz ").await.unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), slow.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert!(response.is_empty());
        tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(tokio::net::TcpListener::bind(address).await.is_ok());
    }
}
