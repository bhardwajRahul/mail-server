/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::dummy_tls_acceptor;
use crate::directory::{DirectoryTest, Item, LookupResult};
use common::listener::limiter::{ConcurrencyLimiter, InFlight};
use directory::{QueryParams, backend::RcptType};
use mail_parser::decoders::base64::base64_decode;
use mail_send::Credentials;
use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::watch,
};
use tokio_rustls::TlsAcceptor;

#[tokio::test]
async fn lmtp_directory() {
    // Spawn mock LMTP server
    let shutdown = spawn_mock_lmtp_server(5);
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Obtain directory handle
    let mut config = DirectoryTest::new(None).await;
    let handle = config.directories.directories.remove("smtp").unwrap();
    let core = config.server;

    // Basic lookup
    let tests = vec![
        (Item::IsAccount("john-ok@domain".into()), LookupResult::True),
        (
            Item::IsAccount("john-bad@domain".into()),
            LookupResult::False,
        ),
        (
            Item::Verify("john-ok@domain".into()),
            LookupResult::Values(vec!["john-ok@domain".into()]),
        ),
        (
            Item::Verify("doesnot@exist.org".into()),
            LookupResult::False,
        ),
        (
            Item::Expand("sales-ok,item1,item2,item3".into()),
            LookupResult::Values(vec![
                "sales-ok".into(),
                "item1".into(),
                "item2".into(),
                "item3".into(),
            ]),
        ),
        (Item::Expand("other".into()), LookupResult::False),
        (
            Item::Authenticate(Credentials::Plain {
                username: "john".into(),
                secret: "ok".into(),
            }),
            LookupResult::True,
        ),
        (
            Item::Authenticate(Credentials::Plain {
                username: "john".into(),
                secret: "bad".into(),
            }),
            LookupResult::False,
        ),
    ];

    for (item, expected) in &tests {
        let result: LookupResult = match item {
            Item::IsAccount(v) => {
                (core.rcpt(&handle, v, 0).await.unwrap() == RcptType::Mailbox).into()
            }
            Item::Authenticate(v) => handle
                .query(QueryParams::credentials(v).with_return_member_of(true))
                .await
                .unwrap()
                .is_some()
                .into(),
            Item::Verify(v) => match core.vrfy(&handle, v, 0).await {
                Ok(v) => v.into(),
                Err(e) => {
                    if e.matches(trc::EventType::Store(trc::StoreEvent::NotSupported)) {
                        LookupResult::False
                    } else {
                        panic!("Unexpected error: {e:?}")
                    }
                }
            },
            Item::Expand(v) => match core.expn(&handle, v, 0).await {
                Ok(v) => v.into(),
                Err(e) => {
                    if e.matches(trc::EventType::Store(trc::StoreEvent::NotSupported)) {
                        LookupResult::False
                    } else {
                        panic!("Unexpected error: {e:?}")
                    }
                }
            },
        };

        assert_eq!(&result, expected);
    }

    // Concurrent requests
    let mut requests = Vec::new();
    let core = Arc::new(core);
    for n in 0..100 {
        let (item, expected) = &tests[n % tests.len()];
        let item = item.append(n);
        let item_clone = item.clone();
        let handle = handle.clone();
        let core = core.clone();
        requests.push((
            tokio::spawn(async move {
                let result: LookupResult = match &item {
                    Item::IsAccount(v) => {
                        (core.rcpt(&handle, v, 0).await.unwrap() == RcptType::Mailbox).into()
                    }
                    Item::Authenticate(v) => handle
                        .query(QueryParams::credentials(v).with_return_member_of(true))
                        .await
                        .unwrap()
                        .is_some()
                        .into(),
                    Item::Verify(v) => match core.vrfy(&handle, v, 0).await {
                        Ok(v) => v.into(),
                        Err(e) => {
                            if e.matches(trc::EventType::Store(trc::StoreEvent::NotSupported)) {
                                LookupResult::False
                            } else {
                                panic!("Unexpected error: {e:?}")
                            }
                        }
                    },
                    Item::Expand(v) => match core.expn(&handle, v, 0).await {
                        Ok(v) => v.into(),
                        Err(e) => {
                            if e.matches(trc::EventType::Store(trc::StoreEvent::NotSupported)) {
                                LookupResult::False
                            } else {
                                panic!("Unexpected error: {e:?}")
                            }
                        }
                    },
                };

                result
            }),
            item_clone,
            expected.append(n),
        ));
    }
    for (result, item, expected_result) in requests {
        assert_eq!(
            result.await.unwrap(),
            expected_result,
            "Failed for {item:?}"
        );
    }

    // Shutdown
    shutdown.send(false).ok();

    // Verify that caching works
    TcpStream::connect("127.0.0.1:9199").await.unwrap_err();

    let mut requests = Vec::new();
    for n in 0..100 {
        let (item, expected) = &tests[n % tests.len()];
        if matches!(item, Item::IsAccount(_)) {
            let item = item.append(n);
            let item_clone = item.clone();
            let handle = handle.clone();
            let core = core.clone();
            requests.push((
                tokio::spawn(async move {
                    let result: LookupResult = match &item {
                        Item::IsAccount(v) => {
                            (core.rcpt(&handle, v, 0).await.unwrap() == RcptType::Mailbox).into()
                        }
                        _ => unreachable!(),
                    };

                    result
                }),
                item_clone,
                expected.append(n),
            ));
        }
    }
    assert!(!requests.is_empty());
    for (result, item, expected_result) in requests {
        assert_eq!(
            result.await.unwrap(),
            expected_result,
            "Failed for {item:?}"
        );
    }
}

pub fn spawn_mock_lmtp_server(max_concurrency: u64) -> watch::Sender<bool> {
    let (tx, rx) = watch::channel(true);

    tokio::spawn(async move {
        let listener = TcpListener::bind("127.0.0.1:9199")
            .await
            .unwrap_or_else(|e| {
                panic!("Failed to bind mock SMTP server to 127.0.0.1:9199: {e}");
            });
        let acceptor = dummy_tls_acceptor();
        let limited = ConcurrencyLimiter::new(max_concurrency);
        let mut rx_ = rx.clone();
        loop {
            tokio::select! {
                stream = listener.accept() => {
                    match stream {
                        Ok((stream, _)) => {
                            let acceptor = acceptor.clone();
                            let in_flight = limited.is_allowed();
                            tokio::spawn(accept_smtp(stream, rx.clone(), acceptor, in_flight.into()));
                        }
                        Err(err) => {
                            panic!("Something went wrong: {err}" );
                        }
                    }
                },
                _ = rx_.changed() => {
                    break;
                }
            };
        }
    });

    tx
}

async fn accept_smtp(
    stream: TcpStream,
    mut rx: watch::Receiver<bool>,
    acceptor: Arc<TlsAcceptor>,
    in_flight: Option<InFlight>,
) {
    let mut stream = acceptor.accept(stream).await.unwrap();
    stream
        .write_all(b"220 [127.0.0.1] Clueless host service ready\r\n")
        .await
        .unwrap();

    if in_flight.is_none() {
        eprintln!("WARNING: Concurrency exceeded!");
    }

    let mut buf_u8 = vec![0u8; 1024];

    loop {
        let br = tokio::select! {
            br = stream.read(&mut buf_u8) => {
                match br {
                    Ok(br) => {
                        br
                    }
                    Err(_) => {
                        break;
                    }
                }
            },
            _ = rx.changed() => {
                break;
            }
        };

        let buf = std::str::from_utf8(&buf_u8[0..br]).unwrap();
        let response = if buf.starts_with("LHLO") {
            "250-mx.foobar.org\r\n250 AUTH PLAIN\r\n".into()
        } else if buf.starts_with("MAIL FROM") {
            if buf.contains("<>") || buf.contains("ok@") {
                "250 OK\r\n".into()
            } else {
                "552-I do not\r\n552 like that MAIL FROM.\r\n".into()
            }
        } else if buf.starts_with("RCPT TO") {
            if buf.contains("ok") {
                "250 OK\r\n".into()
            } else {
                "550-I refuse to\r\n550 accept that recipient.\r\n".into()
            }
        } else if buf.starts_with("VRFY") {
            if buf.contains("ok") {
                format!("250 {}\r\n", buf.split_once(' ').unwrap().1)
            } else {
                "550-I refuse to\r\n550 verify that recipient.\r\n".into()
            }
        } else if buf.starts_with("EXPN") {
            if buf.contains("ok") {
                let parts = buf
                    .split_once(' ')
                    .unwrap()
                    .1
                    .split(',')
                    .filter_map(|s| {
                        if !s.is_empty() {
                            s.to_string().into()
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>();
                let mut buf = String::with_capacity(16);
                for (pos, part) in parts.iter().enumerate() {
                    buf.push_str("250");
                    buf.push(if pos == parts.len() - 1 { ' ' } else { '-' });
                    buf.push_str(part);
                    buf.push_str("\r\n");
                }

                buf
            } else {
                "550-I refuse to\r\n550 accept that recipient.\r\n".into()
            }
        } else if buf.starts_with("AUTH PLAIN") {
            let buf = base64_decode(buf.rsplit_once(' ').unwrap().1.as_bytes()).unwrap();
            if String::from_utf8_lossy(&buf).contains("ok") {
                "235 Great success!\r\n".into()
            } else {
                "535 No soup for you\r\n".into()
            }
        } else if buf.starts_with("NOOP") {
            "250 Siesta time\r\n".into()
        } else if buf.starts_with("QUIT") {
            "250 Arrivederci!\r\n".into()
        } else if buf.starts_with("RSET") {
            "250 Your wish is my command.\r\n".into()
        } else {
            panic!("Unknown command: {}", buf.trim());
        };
        //print!("<- {}", response);
        stream.write_all(response.as_bytes()).await.unwrap();

        if buf.contains("bye") || buf.starts_with("QUIT") {
            return;
        }
    }
}
