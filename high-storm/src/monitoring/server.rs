use std::{future::IntoFuture, net::SocketAddr, time::Duration};

use axum::{Router, extract::State, http::header, response::IntoResponse, routing::get};
use metrics_exporter_prometheus::PrometheusHandle;
use metrics_process::Collector;
use tokio::{net::TcpListener, time::MissedTickBehavior};

/// Without a built-in exporter nothing else drains histogram samples.
const UPKEEP_INTERVAL: Duration = Duration::from_secs(5);
const CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

pub struct MetricsServer {
    listener: TcpListener,
    handle: PrometheusHandle,
}

impl MetricsServer {
    pub async fn bind(address: SocketAddr, handle: PrometheusHandle) -> std::io::Result<Self> {
        Ok(Self {
            listener: TcpListener::bind(address).await?,
            handle,
        })
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub async fn run(self) -> std::io::Result<()> {
        let mut upkeep = tokio::time::interval(UPKEEP_INTERVAL);
        upkeep.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let serve = axum::serve(self.listener, router(self.handle.clone())).into_future();
        tokio::pin!(serve);

        loop {
            tokio::select! {
                result = &mut serve => return result,
                _ = upkeep.tick() => self.handle.run_upkeep(),
            }
        }
    }
}

#[derive(Clone)]
struct MetricsState {
    handle: PrometheusHandle,
    process: Collector,
}

fn router(handle: PrometheusHandle) -> Router {
    Router::new()
        .route("/metrics", get(render))
        .with_state(MetricsState {
            handle,
            process: Collector::default(),
        })
}

async fn render(State(state): State<MetricsState>) -> impl IntoResponse {
    state.process.collect();
    (
        [(header::CONTENT_TYPE, CONTENT_TYPE)],
        state.handle.render(),
    )
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

        let response = router(handle).oneshot(request("/metrics")).await.unwrap();

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
    async fn serves_nothing_else() {
        let handle = builder().unwrap().build_recorder().handle();

        let response = router(handle).oneshot(request("/")).await.unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
