//! The box's own client -- the flow plane -- on the tunnel listener.
//!
//! The flow plane is the routing channel: the box's own client (`mirage-vpn
//! connect`) opens a flow and the bytes are pumped through it. The customer's
//! client does not speak it any more: that one speaks the packet plane (see
//! `plane_session.rs`).

use std::collections::VecDeque;
use std::sync::Arc;

use mirage_vpn::flow::{FlowError, Target};
use mirage_vpn::session::serve;
use mirage_vpn::socks5::{ExitConnector, ExitStream};
use mirage_vpn::testing::MemoryTunnel;
use tokio::sync::{Mutex, Notify};

/// The exit: it remembers the target and echoes the bytes back.
struct EchoExit {
    seen: Arc<Mutex<Vec<Target>>>,
    queue: Arc<Mutex<VecDeque<u8>>>,
    notify: Arc<Notify>,
}

#[async_trait::async_trait]
impl ExitConnector for EchoExit {
    async fn connect(&self, target: &Target) -> Result<Box<dyn ExitStream>, FlowError> {
        self.seen.lock().await.push(target.clone());
        Ok(Box::new(EchoStream {
            queue: Arc::clone(&self.queue),
            notify: Arc::clone(&self.notify),
        }))
    }
}

/// The connection to the target.
struct EchoStream {
    queue: Arc<Mutex<VecDeque<u8>>>,
    notify: Arc<Notify>,
}

#[async_trait::async_trait]
impl ExitStream for EchoStream {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        loop {
            {
                let mut queue = self.queue.lock().await;
                if !queue.is_empty() {
                    let count = queue.len().min(buf.len());
                    let bytes: Vec<u8> = queue.drain(..count).collect();
                    buf[..count].copy_from_slice(&bytes);
                    return Ok(count);
                }
            }
            // Nothing yet: wait for the bytes to come.
            self.notify.notified().await;
        }
    }

    async fn write(&mut self, buf: &[u8]) -> Result<(), std::io::Error> {
        self.queue.lock().await.extend(buf.iter().copied());
        self.notify.notify_one();
        Ok(())
    }
}

/// The box's own client speaks the flow plane on the tunnel listener.
#[tokio::test]
async fn the_flow_plane_still_works_on_the_tunnel_listener() {
    let (client, server) = MemoryTunnel::pair();
    let mut client = client;

    let seen = Arc::new(Mutex::new(Vec::new()));
    let queue = Arc::new(Mutex::new(VecDeque::new()));
    let notify = Arc::new(Notify::new());
    let connector: Arc<dyn ExitConnector> = Arc::new(EchoExit {
        seen: Arc::clone(&seen),
        queue: Arc::clone(&queue),
        notify: Arc::clone(&notify),
    });

    let served = tokio::spawn(async move {
        serve(
            server,
            connector,
            Some("0.0.0.0:41443".parse().expect("an address")),
            None,
            None,
        )
        .await
    });

    // The flow plane's first message is an Open: the channel's length
    // prefix, then the message.
    let message = mirage_vpn::flow::FlowMessage::Open {
        id: 1,
        target: Target::Named("example.com".to_owned(), 443),
    }
    .encode();
    let mut first = Vec::new();
    first.extend_from_slice(&(message.len() as u16).to_be_bytes());
    first.extend_from_slice(&message);
    client.send(&first).await.expect("a send");

    // The box opened the target: the flow plane, not the edge wire.
    let mut opened = false;
    for _ in 0..50 {
        if !seen.lock().await.is_empty() {
            opened = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(opened, "the flow plane did not reach the exit");

    served.abort();
}
