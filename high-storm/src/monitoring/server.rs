use std::{
    future::{Future, IntoFuture},
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use axum::{
    Router,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use metrics::counter;
use metrics_exporter_prometheus::PrometheusHandle;
use metrics_process::Collector;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore},
    time::{MissedTickBehavior, Sleep},
};

use super::names;

/// Without a built-in exporter nothing else drains histogram samples.
const UPKEEP_INTERVAL: Duration = Duration::from_secs(5);
const CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";
/// Enough for a few Prometheus servers, while the node's file descriptors,
/// shared with the P2P port and the API, stay out of a scraper's reach.
const MAX_CONNECTIONS: usize = 8;
/// A connection is closed this long after it opened, so idle ones cannot hold
/// the few slots; a scraper simply reconnects.
const CONNECTION_LIFETIME: Duration = Duration::from_secs(60);

pub struct MetricsServer {
    listener: TcpListener,
    handle: PrometheusHandle,
    bearer_token: Option<String>,
}

impl MetricsServer {
    pub async fn bind(
        address: SocketAddr,
        handle: PrometheusHandle,
        bearer_token: Option<String>,
    ) -> io::Result<Self> {
        Ok(Self {
            listener: TcpListener::bind(address).await?,
            handle,
            bearer_token,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub async fn run(self) -> io::Result<()> {
        let mut upkeep = tokio::time::interval(UPKEEP_INTERVAL);
        upkeep.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let listener = LimitedListener {
            listener: self.listener,
            connections: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
        };
        let serve =
            axum::serve(listener, router(self.handle.clone(), self.bearer_token)).into_future();
        tokio::pin!(serve);

        loop {
            tokio::select! {
                result = &mut serve => return result,
                _ = upkeep.tick() => self.handle.run_upkeep(),
            }
        }
    }
}

struct LimitedListener {
    listener: TcpListener,
    connections: Arc<Semaphore>,
}

impl axum::serve::Listener for LimitedListener {
    type Io = LimitedConnection;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (stream, address) = axum::serve::Listener::accept(&mut self.listener).await;
            let Ok(permit) = self.connections.clone().try_acquire_owned() else {
                counter!(names::METRICS_CONNECTIONS_REJECTED).increment(1);
                continue;
            };
            return (
                LimitedConnection {
                    stream,
                    closes_at: Box::pin(tokio::time::sleep(CONNECTION_LIFETIME)),
                    _permit: permit,
                },
                address,
            );
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }
}

struct LimitedConnection {
    stream: TcpStream,
    closes_at: Pin<Box<Sleep>>,
    _permit: OwnedSemaphorePermit,
}

impl LimitedConnection {
    fn expired(&mut self, context: &mut Context<'_>) -> bool {
        self.closes_at.as_mut().poll(context).is_ready()
    }
}

impl AsyncRead for LimitedConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.expired(context) {
            return Poll::Ready(Err(io::ErrorKind::TimedOut.into()));
        }
        Pin::new(&mut self.stream).poll_read(context, buffer)
    }
}

impl AsyncWrite for LimitedConnection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.expired(context) {
            return Poll::Ready(Err(io::ErrorKind::TimedOut.into()));
        }
        Pin::new(&mut self.stream).poll_write(context, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(context)
    }
}

#[derive(Clone)]
struct MetricsState {
    handle: PrometheusHandle,
    process: Collector,
    bearer_token: Option<Arc<str>>,
}

fn router(handle: PrometheusHandle, bearer_token: Option<String>) -> Router {
    Router::new()
        .route("/metrics", get(render))
        .with_state(MetricsState {
            handle,
            process: Collector::default(),
            bearer_token: bearer_token.map(Arc::from),
        })
}

async fn render(State(state): State<MetricsState>, headers: HeaderMap) -> Response {
    if let Some(expected) = &state.bearer_token {
        let given = headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "));
        if !given.is_some_and(|given| same_token(given.as_bytes(), expected.as_bytes())) {
            return StatusCode::UNAUTHORIZED.into_response();
        }
    }
    state.process.collect();
    (
        [(header::CONTENT_TYPE, CONTENT_TYPE)],
        state.handle.render(),
    )
        .into_response()
}

/// Compares every byte, so the time taken does not tell how much matched.
fn same_token(given: &[u8], expected: &[u8]) -> bool {
    given.len() == expected.len()
        && given
            .iter()
            .zip(expected)
            .fold(0, |difference, (given, expected)| {
                difference | (given ^ expected)
            })
            == 0
}

#[cfg(test)]
mod tests {
    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    use super::*;
    use crate::monitoring::{builder, record_build_info};

    fn request(path: &str) -> Request<Body> {
        Request::builder().uri(path).body(Body::empty()).unwrap()
    }

    #[tokio::test]
    async fn serves_rendered_metrics() {
        let recorder = builder().unwrap().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, record_build_info);

        let response = router(handle, None)
            .oneshot(request("/metrics"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CONTENT_TYPE], CONTENT_TYPE);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert!(
            String::from_utf8(body.to_vec())
                .unwrap()
                .contains("high_storm_build_info")
        );
    }

    #[tokio::test]
    async fn serves_process_metrics() {
        let recorder = builder().unwrap().build_recorder();
        let handle = recorder.handle();
        let _local = metrics::set_default_local_recorder(&recorder);

        let response = router(handle, None)
            .oneshot(request("/metrics"))
            .await
            .unwrap();

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert!(
            String::from_utf8(body.to_vec())
                .unwrap()
                .contains("process_resident_memory_bytes")
        );
    }

    #[tokio::test]
    async fn serves_nothing_else() {
        let handle = builder().unwrap().build_recorder().handle();

        let response = router(handle, None).oneshot(request("/")).await.unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn requires_the_bearer_token_when_one_is_set() {
        let handle = builder().unwrap().build_recorder().handle();
        let app = router(handle, Some("secret".into()));
        let with = |token: &str| {
            Request::builder()
                .uri("/metrics")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap()
        };

        for (request, status) in [
            (request("/metrics"), StatusCode::UNAUTHORIZED),
            (with("secreT"), StatusCode::UNAUTHORIZED),
            (with("secret"), StatusCode::OK),
        ] {
            assert_eq!(app.clone().oneshot(request).await.unwrap().status(), status);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn caps_connections_and_closes_them_after_their_lifetime() {
        use tokio::io::AsyncReadExt;

        let recorder = builder().unwrap().build_recorder();
        let _local = metrics::set_default_local_recorder(&recorder);
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = tcp.local_addr().unwrap();
        let mut listener = LimitedListener {
            listener: tcp,
            connections: Arc::new(Semaphore::new(1)),
        };
        let _first = TcpStream::connect(address).await.unwrap();
        let (mut accepted, _) = axum::serve::Listener::accept(&mut listener).await;
        let mut refused = TcpStream::connect(address).await.unwrap();
        let accept =
            tokio::spawn(async move { axum::serve::Listener::accept(&mut listener).await });

        // The second connection is closed without an answer while the first
        // holds the only slot.
        let mut buffer = [0; 1];
        assert!(matches!(refused.read(&mut buffer).await, Ok(0) | Err(_)));
        assert!(!accept.is_finished());
        // The paused clock jumps to the deadline once every task waits.
        assert_eq!(
            accepted.read(&mut buffer).await.unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        drop(accepted);
        let _replacement = TcpStream::connect(address).await.unwrap();
        accept.await.unwrap();
        assert!(
            recorder
                .handle()
                .render()
                .contains("high_storm_metrics_connections_rejected_total 1")
        );
    }

    #[test]
    fn compares_whole_tokens() {
        assert!(same_token(b"secret", b"secret"));
        assert!(!same_token(b"secret", b"secreT"));
        assert!(!same_token(b"secret", b"secret!"));
    }
}
