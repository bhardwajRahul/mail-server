/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
    time::Duration,
};

use common::listener::blocked::BLOCKED_IP_KEY;
use imap_proto::ResponseType;
use jmap_client::{
    client::{Client, Credentials},
    core::set::{SetError, SetErrorType},
    mailbox::{self},
};
use jmap_proto::types::id::Id;
use store::write::now;

use crate::{
    directory::internal::TestInternalDirectory,
    imap::{ImapConnection, Type},
    jmap::{assert_is_empty, mailbox::destroy_all_mailboxes},
};

use super::JMAPTest;

pub async fn test(params: &mut JMAPTest) {
    println!("Running Authorization tests...");

    // Create test account
    let server = params.server.clone();
    let account_id = Id::from(
        server
            .core
            .storage
            .data
            .create_test_user(
                "jdoe@example.com",
                "12345",
                "John Doe",
                &["jdoe@example.com", "john.doe@example.com"],
            )
            .await,
    )
    .to_string();

    // Reset rate limiters
    params.webhook.clear();

    // Incorrect passwords should be rejected with a 401 error
    assert!(matches!(
        Client::new()
            .credentials(Credentials::basic("jdoe@example.com", "abcde"))
            .accept_invalid_certs(true) .follow_redirects(["127.0.0.1"])
            .connect("https://127.0.0.1:8899")
            .await,
        Err(jmap_client::Error::Problem(err)) if err.status() == Some(401)));

    // Wait until the beginning of the 5 seconds bucket
    const LIMIT: u64 = 5;
    let now = now();
    let range_start = now / LIMIT;
    let range_end = (range_start * LIMIT) + LIMIT;
    tokio::time::sleep(Duration::from_secs(range_end - now)).await;

    // Test fail2ban
    assert_eq!(
        server
            .core
            .storage
            .config
            .get(format!("{BLOCKED_IP_KEY}.127.0.0.1"))
            .await
            .unwrap(),
        None
    );
    for n in 0..98 {
        match Client::new()
            .credentials(Credentials::basic(
                "not_an_account@example.com",
                &format!("brute_force{}", n),
            ))
            .accept_invalid_certs(true)
            .follow_redirects(["127.0.0.1"])
            .connect("https://127.0.0.1:8899")
            .await
        {
            Err(jmap_client::Error::Problem(_)) => {}
            Err(err) => {
                panic!("Unexpected response: {:?}", err);
            }
            Ok(_) => {
                panic!("Unexpected success");
            }
        }
    }

    let mut imap = ImapConnection::connect(b"_x ").await;
    imap.send("AUTHENTICATE PLAIN AGpvaG4AY2hpbWljaGFuZ2Fz")
        .await;
    imap.assert_read(Type::Tagged, ResponseType::No).await;

    // There are already 100 failed login attempts for this IP address
    // so the next one should be rejected, even if done over IMAP
    imap.send("AUTHENTICATE PLAIN AGpvaG4AY2hpbWljaGFuZ2Fz")
        .await;
    imap.assert_disconnect().await;

    // Make sure the IP address is blocked
    assert_eq!(
        server
            .core
            .storage
            .config
            .get(format!("{BLOCKED_IP_KEY}.127.0.0.1"))
            .await
            .unwrap(),
        Some(String::new())
    );
    ImapConnection::connect(b"_y ")
        .await
        .assert_disconnect()
        .await;

    // Lift ban
    server
        .core
        .storage
        .config
        .clear(format!("{BLOCKED_IP_KEY}.127.0.0.1"))
        .await
        .unwrap();
    server
        .inner
        .data
        .blocked_ips
        .write()
        .remove(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));

    // Valid authentication requests should not be rate limited
    for _ in 0..110 {
        Client::new()
            .credentials(Credentials::basic("jdoe@example.com", "12345"))
            .accept_invalid_certs(true)
            .follow_redirects(["127.0.0.1"])
            .connect("https://127.0.0.1:8899")
            .await
            .unwrap();
    }

    // Login with the correct credentials
    let client = Client::new()
        .credentials(Credentials::basic("jdoe@example.com", "12345"))
        .accept_invalid_certs(true)
        .follow_redirects(["127.0.0.1"])
        .connect("https://127.0.0.1:8899")
        .await
        .unwrap();
    assert_eq!(client.session().username(), "jdoe@example.com");
    assert_eq!(
        client.session().account(&account_id).unwrap().name(),
        "John Doe"
    );
    assert!(client.session().account(&account_id).unwrap().is_personal());

    // Uploads up to 5000000 bytes should be allowed
    assert_eq!(
        client
            .upload(None, vec![b'A'; 5000000], None)
            .await
            .unwrap()
            .size(),
        5000000
    );
    assert!(
        client
            .upload(None, vec![b'A'; 5000001], None)
            .await
            .is_err()
    );

    // Users should be allowed to create identities only
    // using email addresses associated to their principal
    let iid1 = client
        .identity_create("John Doe", "jdoe@example.com")
        .await
        .unwrap()
        .take_id();
    let iid2 = client
        .identity_create("John Doe (secondary)", "john.doe@example.com")
        .await
        .unwrap()
        .take_id();
    assert!(matches!(
        client
            .identity_create("John the Spammer", "spammy@mcspamface.com")
            .await,
        Err(jmap_client::Error::Set(SetError {
            type_: SetErrorType::InvalidProperties,
            ..
        }))
    ));
    client.identity_destroy(&iid1).await.unwrap();
    client.identity_destroy(&iid2).await.unwrap();

    // Concurrent requests check
    let client = Arc::new(client);
    for _ in 0..8 {
        let client_ = client.clone();
        tokio::spawn(async move {
            let _ = client_
                .mailbox_query(
                    mailbox::query::Filter::name("__sleep").into(),
                    [mailbox::query::Comparator::name()].into(),
                )
                .await;
        });
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(matches!(
        client
            .mailbox_query(
                mailbox::query::Filter::name("__sleep").into(),
                [mailbox::query::Comparator::name()].into(),
            )
            .await,
            Err(jmap_client::Error::Problem(err)) if err.status() == Some(400)));

    // Wait for sleep to be done
    tokio::time::sleep(Duration::from_millis(1000)).await;

    // Concurrent upload test
    for _ in 0..4 {
        let client_ = client.clone();
        tokio::spawn(async move {
            client_.upload(None, b"sleep".to_vec(), None).await.unwrap();
        });
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(matches!(
        client.upload(None, b"sleep".to_vec(), None).await,
        Err(jmap_client::Error::Problem(err)) if err.status() == Some(400)));

    // Destroy test accounts
    params.client.set_default_account_id(&account_id);
    destroy_all_mailboxes(params).await;
    assert_is_empty(server).await;

    // Check webhook events
    params
        .webhook
        .assert_contains(&["auth.failed", "auth.success", "security.authentication-ban"]);
}
