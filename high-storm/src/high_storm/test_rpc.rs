use std::net::SocketAddr;

use tokio::task::JoinHandle;

/// Serves `app` on a free local port, for tests that talk to a mock RPC server.
pub(crate) async fn serve(app: axum::Router) -> (SocketAddr, JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (address, server)
}
