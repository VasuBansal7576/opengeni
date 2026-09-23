//! SEC-02 reproduction: a `mode:"view"` ogs_ token must not be able to inject
//! DesktopInput into a desktop channel. On the vulnerable build the relay
//! forwards it verbatim to the agent (the bug); on the fixed build the message
//! is dropped/not delivered.

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

const SECRET: &str = "sec02-repro-secret";
const WORKSPACE: &str = "11111111-1111-4111-8111-111111111111";
const AGENT: &str = "44444444-4444-4444-8444-444444444444";
const DESKTOP_PORT: u32 = 6080;
const CHANNEL: &str = "ch-sec02";

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

fn viewer_token_view() -> String {
    mint(
        "ogs_",
        &format!(
            r#"{{"workspaceId":"{WORKSPACE}","sessionId":"22222222-2222-4222-8222-222222222222","viewerId":"33333333-3333-4333-8333-333333333333","leaseEpoch":0,"mode":"view","port":{DESKTOP_PORT},"exp":4102444800,"agentId":"{AGENT}","channelId":"{CHANNEL}"}}"#
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
async fn sec02_view_token_desktop_input() {
    let port = free_port().await;
    let mut config = RelayConfig::for_test(SECRET);
    config.bind = format!("127.0.0.1:{port}");
    config.stream_control_enabled = true;
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

    // Producer (agent) registers on the desktop channel.
    let mut producer = RelayChannel::register(ChannelConfig {
        channel: v1::StreamChannel {
            channel_id: CHANNEL.to_string(),
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

    // Viewer with a mode:"view" token attaches to the same desktop channel.
    let url = format!("{base}?ws={WORKSPACE}&agent={AGENT}&port={DESKTOP_PORT}&channel={CHANNEL}");
    let (mut socket, _resp) = tokio_tungstenite::connect_async(&url).await.expect("dial");
    let open = RelayMessage::Open(v1::StreamOpen {
        channel: Some(v1::StreamChannel {
            channel_id: CHANNEL.to_string(),
            workspace_id: WORKSPACE.to_string(),
            agent_id: AGENT.to_string(),
            kind: v1::StreamKind::Desktop as i32,
            port: DESKTOP_PORT,
        }),
        token: viewer_token_view(),
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
    println!("viewer ack accepted={} err={:?}", ack.accepted, ack.error);

    // Viewer injects a keystroke via DesktopInput.
    let input = RelayMessage::DesktopInput(v1::DesktopInput {
        channel_id: CHANNEL.to_string(),
        event: Some(v1::desktop_input::Event::Key(v1::KeyEvent {
            key: "x".to_string(),
            is_text: true,
            action: v1::KeyAction::Press as i32,
        })),
    });
    socket
        .send(WsMessage::Binary(input.encode()))
        .await
        .expect("send input");

    // Did the producer receive injected input from a VIEW-only token?
    let got = tokio::time::timeout(Duration::from_secs(3), producer.recv()).await;
    match got {
        Ok(Ok(Some(RelayMessage::DesktopInput(_)))) => {
            println!("SEC02_RESULT=VULNERABLE: view token's DesktopInput reached the agent");
        }
        Ok(Ok(Some(other))) => {
            println!("SEC02_RESULT=OTHER: producer received {other:?}");
        }
        Ok(Ok(None)) => println!("SEC02_RESULT=CLOSED: producer channel ended"),
        Ok(Err(e)) => println!("SEC02_RESULT=RECV_ERR: {e}"),
        Err(_) => println!("SEC02_RESULT=SAFE: no input delivered to agent within 3s"),
    }
    let _ = tx.send(());
}
