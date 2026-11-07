//! A tunnel that keeps what was written in it — for the tests.
//!
//! The tests of the flow plane need two sessions that talk to each other
//! without a network. This is that: two queues, and a tunnel at each end.
//!
//! The queue is a mutex and a notify, and not a channel: a tunnel has to be
//! `Sync` — the session core hands it out as a `Box<dyn Tunnel>` — and a
//! receiver is not.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use mirage_core::error::MirageError;
use mirage_protocol::traits::{Tunnel, TransportInfo};
use tokio::sync::Notify;

/// What the queue holds.
#[derive(Default)]
struct Inner {
    items: VecDeque<Vec<u8>>,
    closed: bool,
}

/// A queue of messages, with a doorbell.
#[derive(Default)]
struct Queue {
    inner: Mutex<Inner>,
    notify: Notify,
}

impl Queue {
    /// Put a message in and ring the bell.
    fn push(&self, item: Vec<u8>) {
        {
            let mut guard = self.inner.lock().expect("the queue lock");
            guard.items.push_back(item);
        }
        self.notify.notify_one();
    }

    /// Take the next message, waiting for one when the queue is empty.
    async fn pop(&self) -> Option<Vec<u8>> {
        loop {
            // The bell is registered before the queue is looked at: a message
            // that arrives in between rings a bell nobody is waiting for
            // yet, and the bell keeps the permit.
            let ringing = self.notify.notified();
            {
                let mut guard = self.inner.lock().expect("the queue lock");
                if let Some(item) = guard.items.pop_front() {
                    return Some(item);
                }
                if guard.closed {
                    return None;
                }
            }
            ringing.await;
        }
    }

    /// Close the queue.
    fn close(&self) {
        {
            let mut guard = self.inner.lock().expect("the queue lock");
            guard.closed = true;
        }
        self.notify.notify_waiters();
    }
}

/// A tunnel over a queue.
pub struct MemoryTunnel {
    /// Where the bytes of this tunnel go.
    outbox: Arc<Queue>,
    /// Where the bytes of the other tunnel come from.
    inbox: Arc<Queue>,
    info: TransportInfo,
    /// The bytes of the last message that did not fit into the buffer.
    drain: Vec<u8>,
}

impl MemoryTunnel {
    /// Two tunnels that talk to each other.
    pub fn pair() -> (Box<dyn Tunnel>, Box<dyn Tunnel>) {
        let (left, right) = (Arc::new(Queue::default()), Arc::new(Queue::default()));
        let address = "127.0.0.1:1".parse().expect("an address");
        (
            Box::new(Self {
                outbox: Arc::clone(&left),
                inbox: Arc::clone(&right),
                info: TransportInfo::tcp_raw(address),
                drain: Vec::new(),
            }),
            Box::new(Self {
                outbox: right,
                inbox: left,
                info: TransportInfo::tcp_raw(address),
                drain: Vec::new(),
            }),
        )
    }
}

#[async_trait::async_trait]
impl Tunnel for MemoryTunnel {
    async fn send(&mut self, data: &[u8]) -> Result<(), MirageError> {
        self.outbox.push(data.to_vec());
        Ok(())
    }

    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, MirageError> {
        if self.drain.is_empty() {
            let Some(message) = self.inbox.pop().await else {
                return Ok(0);
            };
            self.drain = message;
        }
        let count = self.drain.len().min(buf.len());
        buf[..count].copy_from_slice(&self.drain[..count]);
        self.drain.drain(..count);
        Ok(count)
    }

    async fn close(&mut self) -> Result<(), MirageError> {
        self.outbox.close();
        Ok(())
    }

    fn transport_info(&self) -> &TransportInfo {
        &self.info
    }
}
