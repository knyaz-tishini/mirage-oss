use mirage_mux::tokio_compat::{SessionHandle, TokioIoCompat, TokioMuxStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn concurrent_streams_bidirectional() {
    let (client_io, server_io) = tokio::io::duplex(256 * 1024);
    let client = SessionHandle::client(TokioIoCompat(client_io));
    let server = std::sync::Arc::new(SessionHandle::server(TokioIoCompat(server_io)));
    let server2 = server.clone();

    let echo_handle = tokio::spawn(async move {
        for _ in 0..32 {
            let mut stream = TokioMuxStream(server2.accept_stream().await.unwrap());
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                loop {
                    let n = match stream.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => n,
                        Err(_) => break,
                    };
                    if stream.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    let mut handles = Vec::new();
    for i in 0u32..32 {
        let mut stream = TokioMuxStream(client.open_stream().await.unwrap());
        handles.push(tokio::spawn(async move {
            let data: Vec<u8> = (0..65536u32).map(|j| ((i + j) % 256) as u8).collect();
            stream.write_all(&data).await.unwrap();
            stream.shutdown().await.unwrap();

            let mut received = Vec::new();
            let mut buf = vec![0u8; 8192];
            loop {
                let n = match stream.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(_) => break,
                };
                received.extend_from_slice(&buf[..n]);
            }
            assert_eq!(
                received.len(),
                65536,
                "stream {i}: expected 64KB, got {} bytes",
                received.len()
            );
            assert_eq!(received, data, "stream {i}: data mismatch");
        }));
    }

    for h in handles {
        h.await.unwrap();
    }

    echo_handle.abort();
}

#[tokio::test]
async fn large_payload_single_stream() {
    let (client_io, server_io) = tokio::io::duplex(256 * 1024);
    let client = SessionHandle::client(TokioIoCompat(client_io));
    let server = SessionHandle::server(TokioIoCompat(server_io));

    let mut c_stream = TokioMuxStream(client.open_stream().await.unwrap());

    let data: Vec<u8> = (0..1_048_576u32).map(|i| (i % 251) as u8).collect();
    let data_clone = data.clone();

    // The writer starts before the accept: the mux opens lazily, so the first
    // write is what puts this stream in front of the server. See the
    // `basic.rs` module doc.
    let writer = tokio::spawn(async move {
        c_stream.write_all(&data_clone).await.unwrap();
        c_stream.shutdown().await.unwrap();
    });

    let s_stream = TokioMuxStream(server.accept_stream().await.unwrap());
    let mut s_stream = s_stream;

    let reader = tokio::spawn(async move {
        let mut received = Vec::new();
        let mut buf = vec![0u8; 8192];
        loop {
            let n = match s_stream.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            received.extend_from_slice(&buf[..n]);
        }
        assert_eq!(received.len(), data.len());
        assert_eq!(received, data);
    });

    writer.await.unwrap();
    reader.await.unwrap();
}
