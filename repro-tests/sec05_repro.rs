//! SEC-05 reproduction: a viewer token minted for one channel must not attach to
//! a DIFFERENT channel. On the vulnerable build the token is only workspace+port
//! scoped, so the same token can snoop any channel on that port (the bug).

use std::time::Duration;

use base64::Engine as _;
use futures_util::{SinkExt as _, StreamExt as _};
use hmac::{Hmac, Mac};
use opengeni_agent_proto::v1;
use opengeni_agent_stream::channel::{ChannelConfig, RelayChannel};
use opengeni_agent_stream::codec::RelayMessage;
use opengeni_relay::{serve, RelayConfig, RelayMetrics};
use sha2::Sha256;
use tokio_tungstenite::tungstenite::Message as WsMessage;

type HmacSha256 = Hmac<Sha256>;

const SECRET: &str = "sec05-repro-secret";
const WORKSPACE: &str = "11111111-1111-4111-8111-111111111111";
const AGENT: &str = "44444444-4444-4444-8444-444444444444";
const DESKTOP_PORT: u32 = 6080;

fn mint(prefix: &str, payload_json: &str) -> String {
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload_json);
    let mut mac = HmacSha256::new_from_slice(SECRET.as_bytes()).unwrap();
    mac.update(encoded.as_bytes());
    let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    format!("{prefix}{encoded}.{sig}")
}

fn agent_token() -> String {
    mint(
        "ogr_",
        &format!(r#"{{"workspaceId":"{WORKSPACE}","agentId":"{AGENT}","exp":4102444800}}"#),
    )
}

// Token minted WITHOUT channel binding claims (the legacy shape).
fn viewer_token_unbound() -> String {
    mint(
        "ogs_",
        &format!(
            r#"{{"workspaceId":"{WORKSPACE}","sessionId":"22222222-2222-4222-8222-222222222222","viewerId":"33333333-3333-4333-8333-333333333333","leaseEpoch":0,"mode":"view","port":{DESKTOP_PORT},"exp":4102444800}}"#
        ),
    )
}

async fn free_port() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    drop(l);
    port
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sec05_unbound_token_cross_channel() {
    let port = free_port().await;
    let mut config = RelayConfig::for_test(SECRET);
    config.bind = format!("127.0.0.1:{port}");
    let metrics = RelayMetrics::new();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let m = metrics.clone();
    tokio::spawn(async move {
        let _ = serve(config, m, async {
            let _ = rx.await;
        })
        .await;
    });
    let base = format!("ws://127.0.0.1:{port}/stream");
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // Producer registers channel "ch-victim".
    let _producer = RelayChannel::register(ChannelConfig {
        channel: v1::StreamChannel {
            channel_id: "ch-victim".to_string(),
            workspace_id: WORKSPACE.to_string(),
            agent_id: AGENT.to_string(),
            kind: v1::StreamKind::Desktop as i32,
            port: DESKTOP_PORT,
        },
        token: agent_token(),
        relay_url: base.clone(),
    })
    .await
    .expect("producer register");

    // Attacker holds a view token minted for SOME session; attaches to ch-victim.
    let url = format!("{base}?ws={WORKSPACE}&agent={AGENT}&port={DESKTOP_PORT}&channel=ch-victim");
    let (mut socket, _resp) = tokio_tungstenite::connect_async(&url).await.expect("dial");
    let open = RelayMessage::Open(v1::StreamOpen {
        channel: Some(v1::StreamChannel {
            channel_id: "ch-victim".to_string(),
            workspace_id: WORKSPACE.to_string(),
            agent_id: AGENT.to_string(),
            kind: v1::StreamKind::Desktop as i32,
            port: DESKTOP_PORT,
        }),
        token: viewer_token_unbound(),
        role: v1::StreamRole::Client as i32,
        resume_from_seq: 0,
    });
    socket
        .send(WsMessage::Binary(open.encode()))
        .await
        .expect("send open");

    let ack = loop {
        match socket.next().await {
            Some(Ok(WsMessage::Binary(b))) => match RelayMessage::decode(&b) {
                Ok(RelayMessage::OpenAck(a)) => break a,
                _ => continue,
            },
            other => panic!("expected OpenAck, got {other:?}"),
        }
    };
    if ack.accepted {
        println!("SEC05_RESULT=VULNERABLE: unbound token attached to a foreign channel");
    } else {
        println!("SEC05_RESULT=SAFE: unbound token rejected: {:?}", ack.error);
    }
    let _ = tx.send(());
}
