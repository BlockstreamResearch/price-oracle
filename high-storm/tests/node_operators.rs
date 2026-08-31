use high_storm::{
    db::Database,
    ipc::{IpcServer, NodeOperatorCommand, NodeOperatorResponse, send_command},
};
use secp256k1_zkp::{Secp256k1, SecretKey};

#[tokio::test]
async fn adds_lists_and_removes_node_operators() {
    let database = Database::connect("sqlite::memory:", 1).await.unwrap();
    let operators = database.node_operators();
    let public_key = SecretKey::from_slice(&[42; 32])
        .unwrap()
        .public_key(&Secp256k1::new())
        .serialize();

    assert!(operators.add(public_key).await.unwrap());
    assert!(!operators.add(public_key).await.unwrap());
    assert_eq!(operators.list().await.unwrap(), [public_key]);
    assert!(operators.remove(public_key).await.unwrap());
    assert!(!operators.remove(public_key).await.unwrap());
    assert!(operators.list().await.unwrap().is_empty());
}

#[tokio::test]
async fn handles_node_operator_commands_over_ipc() {
    let database = Database::connect("sqlite::memory:", 1).await.unwrap();
    let operators = database.node_operators();

    let socket_path = std::env::temp_dir().join(format!(
        "high-storm-operator-test-{}.sock",
        std::process::id()
    ));
    let server = IpcServer::bind(&socket_path, operators.clone())
        .await
        .unwrap();
    let server_task = tokio::spawn(server.run());

    let public_key = SecretKey::from_slice(&[43; 32])
        .unwrap()
        .public_key(&Secp256k1::new())
        .serialize();
    let encoded_key = hex::encode(public_key);

    let add = NodeOperatorCommand::Add {
        public_key: encoded_key.clone(),
    };
    assert_eq!(
        send_command(&socket_path, &add).await.unwrap(),
        NodeOperatorResponse::Added
    );
    assert_eq!(
        send_command(&socket_path, &add).await.unwrap(),
        NodeOperatorResponse::AlreadyExists
    );
    assert_eq!(operators.list().await.unwrap(), [public_key]);

    assert!(matches!(
        send_command(
            &socket_path,
            &NodeOperatorCommand::Add {
                public_key: "not-a-public-key".to_string(),
            },
        )
        .await
        .unwrap(),
        NodeOperatorResponse::Error(_)
    ));

    let remove = NodeOperatorCommand::Remove {
        public_key: encoded_key,
    };
    assert_eq!(
        send_command(&socket_path, &remove).await.unwrap(),
        NodeOperatorResponse::Removed
    );
    assert_eq!(
        send_command(&socket_path, &remove).await.unwrap(),
        NodeOperatorResponse::NotFound
    );
    assert!(operators.list().await.unwrap().is_empty());

    server_task.abort();
    let _ = server_task.await;
}
