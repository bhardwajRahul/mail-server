/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{Core, Server};
use base64::{Engine, engine::general_purpose};
use dns_update::{
    DnsRecord, DnsRecordType, TsigAlgorithm,
    providers::{ovh::OvhEndpoint, rfc2136::DnsAddress},
};
use registry::schema::{
    enums,
    structs::{DnsManagement, DnsServer, Domain},
};
use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use trc::DnsEvent;
use types::id::Id;

pub struct DnsUpdater {
    pub updater: dns_update::DnsUpdater,
    pub polling_interval: Duration,
    pub propagation_timeout: Duration,
    pub propagation_delay: Option<Duration>,
    pub ttl: Duration,
    core: Arc<Core>,
}

#[cfg(feature = "test_mode")]
pub static DNS_RECORDS: std::sync::LazyLock<
    Arc<std::sync::Mutex<Vec<dns_update::NamedDnsRecord>>>,
> = std::sync::LazyLock::new(|| Arc::new(std::sync::Mutex::new(Vec::new())));

impl DnsUpdater {
    pub async fn build(server: DnsServer, core: Arc<Core>) -> Result<Self, String> {
        match server {
            DnsServer::Tsig(server) => Ok(DnsUpdater {
                polling_interval: server.polling_interval.into_inner(),
                propagation_timeout: server.propagation_timeout.into_inner(),
                propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                ttl: server.ttl.into_inner(),
                core,
                updater: dns_update::DnsUpdater::new_rfc2136_tsig(
                    match server.protocol {
                        enums::IpProtocol::Tcp => DnsAddress::Tcp(SocketAddr::new(
                            server.host.into_inner(),
                            server.port as u16,
                        )),
                        enums::IpProtocol::Udp => DnsAddress::Udp(SocketAddr::new(
                            server.host.into_inner(),
                            server.port as u16,
                        )),
                    },
                    server.key_name,
                    general_purpose::STANDARD
                        .decode(server.key.secret().await?.as_bytes())
                        .map_err(|err| format!("Failed to base64 decode TSIG key: {err}"))?,
                    match server.tsig_algorithm {
                        enums::TsigAlgorithm::HmacMd5 => TsigAlgorithm::HmacMd5,
                        enums::TsigAlgorithm::Gss => TsigAlgorithm::Gss,
                        enums::TsigAlgorithm::HmacSha1 => TsigAlgorithm::HmacSha1,
                        enums::TsigAlgorithm::HmacSha224 => TsigAlgorithm::HmacSha224,
                        enums::TsigAlgorithm::HmacSha256 => TsigAlgorithm::HmacSha256,
                        enums::TsigAlgorithm::HmacSha256128 => TsigAlgorithm::HmacSha256_128,
                        enums::TsigAlgorithm::HmacSha384 => TsigAlgorithm::HmacSha384,
                        enums::TsigAlgorithm::HmacSha384192 => TsigAlgorithm::HmacSha384_192,
                        enums::TsigAlgorithm::HmacSha512 => TsigAlgorithm::HmacSha512,
                        enums::TsigAlgorithm::HmacSha512256 => TsigAlgorithm::HmacSha512_256,
                    },
                )
                .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
            }),
            DnsServer::Sig0(_) => {
                Err("RFC 2136 with SIG(0) authentication is no longer supported".into())
            }
            DnsServer::Cloudflare(server) => {
                let updater = {
                    #[cfg(feature = "test_mode")]
                    match server.email.as_deref() {
                        Some("test@pebble.org") => dns_update::DnsUpdater::new_pebble(
                            "http://localhost:8055",
                            server.timeout.into_inner().into(),
                        ),
                        Some("test@memory.org") => {
                            dns_update::DnsUpdater::new_in_memory(DNS_RECORDS.clone())
                        }
                        _ => dns_update::DnsUpdater::new_cloudflare(
                            server.secret.secret().await?,
                            server.email,
                            server.timeout.into_inner().into(),
                        )
                        .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
                    }

                    #[cfg(not(feature = "test_mode"))]
                    dns_update::DnsUpdater::new_cloudflare(
                        server.secret.secret().await?,
                        server.email,
                        server.timeout.into_inner().into(),
                    )
                    .map_err(|err| format!("Failed to build DNS updater: {}", err))?
                };

                Ok(DnsUpdater {
                    polling_interval: server.polling_interval.into_inner(),
                    propagation_timeout: server.propagation_timeout.into_inner(),
                    propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                    ttl: server.ttl.into_inner(),
                    core,
                    updater,
                })
            }
            DnsServer::DigitalOcean(server) => Ok(DnsUpdater {
                polling_interval: server.polling_interval.into_inner(),
                propagation_timeout: server.propagation_timeout.into_inner(),
                propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                ttl: server.ttl.into_inner(),
                core,
                updater: dns_update::DnsUpdater::new_digitalocean(
                    server.secret.secret().await?,
                    server.timeout.into_inner().into(),
                )
                .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
            }),
            DnsServer::DeSEC(server) => Ok(DnsUpdater {
                polling_interval: server.polling_interval.into_inner(),
                propagation_timeout: server.propagation_timeout.into_inner(),
                propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                ttl: server.ttl.into_inner(),
                core,
                updater: dns_update::DnsUpdater::new_desec(
                    server.secret.secret().await?,
                    server.timeout.into_inner().into(),
                )
                .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
            }),
            DnsServer::Ovh(server) => Ok(DnsUpdater {
                polling_interval: server.polling_interval.into_inner(),
                propagation_timeout: server.propagation_timeout.into_inner(),
                propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                ttl: server.ttl.into_inner(),
                core,
                updater: dns_update::DnsUpdater::new_ovh(
                    server.application_key,
                    server.application_secret.secret().await?,
                    server.consumer_key.secret().await?,
                    match server.ovh_endpoint {
                        enums::OvhEndpoint::OvhEu => OvhEndpoint::OvhEu,
                        enums::OvhEndpoint::OvhCa => OvhEndpoint::OvhCa,
                        enums::OvhEndpoint::KimsufiEu => OvhEndpoint::KimsufiEu,
                        enums::OvhEndpoint::KimsufiCa => OvhEndpoint::KimsufiCa,
                        enums::OvhEndpoint::SoyoustartEu => OvhEndpoint::SoyoustartEu,
                        enums::OvhEndpoint::SoyoustartCa => OvhEndpoint::SoyoustartCa,
                    },
                    server.timeout.into_inner().into(),
                )
                .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
            }),
            DnsServer::Bunny(server) => Ok(DnsUpdater {
                polling_interval: server.polling_interval.into_inner(),
                propagation_timeout: server.propagation_timeout.into_inner(),
                propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                ttl: server.ttl.into_inner(),
                core,
                updater: dns_update::DnsUpdater::new_bunny(
                    server.secret.secret().await?,
                    server.timeout.into_inner().into(),
                )
                .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
            }),
            DnsServer::Porkbun(server) => Ok(DnsUpdater {
                polling_interval: server.polling_interval.into_inner(),
                propagation_timeout: server.propagation_timeout.into_inner(),
                propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                ttl: server.ttl.into_inner(),
                core,
                updater: dns_update::DnsUpdater::new_porkbun(
                    server.api_key.as_str(),
                    server.secret.secret().await?,
                    server.timeout.into_inner().into(),
                )
                .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
            }),
            DnsServer::Dnsimple(server) => Ok(DnsUpdater {
                polling_interval: server.polling_interval.into_inner(),
                propagation_timeout: server.propagation_timeout.into_inner(),
                propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                ttl: server.ttl.into_inner(),
                core,
                updater: dns_update::DnsUpdater::new_dnsimple(
                    server.secret.secret().await?,
                    server.account_identifier.as_str(),
                    server.timeout.into_inner().into(),
                )
                .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
            }),
            DnsServer::Spaceship(server) => Ok(DnsUpdater {
                polling_interval: server.polling_interval.into_inner(),
                propagation_timeout: server.propagation_timeout.into_inner(),
                propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                ttl: server.ttl.into_inner(),
                core,
                updater: dns_update::DnsUpdater::new_spaceship(
                    server.api_key.as_str(),
                    server.secret.secret().await?,
                    server.timeout.into_inner().into(),
                )
                .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
            }),
            DnsServer::Route53(server) => {
                let secret_access_key = server.secret_access_key.secret().await?.into_owned();
                let session_token = server.session_token.secret().await?.map(|c| c.into_owned());
                let config = dns_update::providers::route53::Route53Config {
                    access_key_id: server.access_key_id,
                    secret_access_key,
                    session_token,
                    region: Some(server.region),
                    hosted_zone_id: server.hosted_zone_id,
                    private_zone_only: Some(server.private_zone_only),
                };
                Ok(DnsUpdater {
                    polling_interval: server.polling_interval.into_inner(),
                    propagation_timeout: server.propagation_timeout.into_inner(),
                    propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                    ttl: server.ttl.into_inner(),
                    core,
                    updater: dns_update::DnsUpdater::new_route53(config)
                        .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
                })
            }
            DnsServer::GoogleCloudDns(server) => {
                let service_account_json = server.service_account_json.secret().await?.into_owned();
                let config = dns_update::providers::google_cloud_dns::GoogleCloudDnsConfig {
                    service_account_json,
                    project_id: server.project_id,
                    managed_zone: server.managed_zone,
                    private_zone: server.private_zone,
                    impersonate_service_account: server.impersonate_service_account,
                    request_timeout: Some(server.timeout.into_inner()),
                };
                Ok(DnsUpdater {
                    polling_interval: server.polling_interval.into_inner(),
                    propagation_timeout: server.propagation_timeout.into_inner(),
                    propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                    ttl: server.ttl.into_inner(),
                    core,
                    updater: dns_update::DnsUpdater::new_google_cloud_dns(config)
                        .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
                })
            }
        }
    }

    pub async fn create(
        &self,
        origin: &str,
        name: &str,
        record: DnsRecord,
        verify: bool,
        delete_before_create: bool,
    ) -> Result<bool, String> {
        // First try deleting the record
        if delete_before_create
            && let Err(err) = self.updater.delete(name, origin, record.as_type()).await
        {
            // Errors are expected if the record does not exist
            trc::event!(
                Dns(DnsEvent::RecordDeletionFailed),
                Hostname = name.to_string(),
                Reason = err.to_string(),
                Details = origin.to_string(),
                Type = record.as_type().as_str(),
            );
        }

        // Create the record
        if let Err(err) = self
            .updater
            .create(name, record.clone(), self.ttl.as_secs() as u32, origin)
            .await
        {
            return Err(format!("Failed to create DNS record: {}", err));
        }

        trc::event!(
            Dns(DnsEvent::RecordCreated),
            Hostname = name.to_string(),
            Details = origin.to_string(),
            Type = record.as_type().as_str(),
            Value = format!("{:?}", record),
        );

        if verify && let DnsRecord::TXT(txt_record) = &record {
            #[cfg(feature = "test_mode")]
            if matches!(
                self.updater,
                dns_update::DnsUpdater::Pebble(_) | dns_update::DnsUpdater::InMemory(_)
            ) {
                return Ok(true);
            }

            // Wait for changes to propagate
            if let Some(initial_wait) = self.propagation_delay {
                tokio::time::sleep(initial_wait).await;
            }
            let wait_until = Instant::now() + self.propagation_timeout;
            let mut did_propagate = false;
            while Instant::now() < wait_until {
                match self.core.smtp.resolvers.dns.txt_raw_lookup(&name).await {
                    Ok(result) => {
                        let result = std::str::from_utf8(&result).unwrap_or_default();
                        if result.contains(txt_record) {
                            did_propagate = true;
                            break;
                        } else {
                            trc::event!(
                                Dns(DnsEvent::RecordNotPropagated),
                                Hostname = name.to_string(),
                                Details = origin.to_string(),
                                Result = result.to_string(),
                                Type = record.as_type().as_str(),
                                Value = format!("{:?}", record),
                            );
                        }
                    }
                    Err(err) => {
                        trc::event!(
                            Dns(DnsEvent::RecordLookupFailed),
                            Hostname = name.to_string(),
                            Details = origin.to_string(),
                            Reason = err.to_string(),
                            Type = record.as_type().as_str(),
                            Value = format!("{:?}", record),
                        );
                    }
                }

                tokio::time::sleep(self.polling_interval).await;
            }

            if did_propagate {
                trc::event!(
                    Dns(DnsEvent::RecordPropagated),
                    Hostname = name.to_string(),
                    Details = origin.to_string(),
                    Type = record.as_type().as_str(),
                    Value = format!("{:?}", record),
                );
            } else {
                trc::event!(
                    Dns(DnsEvent::RecordPropagationTimeout),
                    Hostname = name.to_string(),
                    Details = origin.to_string(),
                    Type = record.as_type().as_str(),
                    Value = format!("{:?}", record),
                );
            }

            Ok(did_propagate)
        } else {
            Ok(true)
        }
    }

    pub async fn delete(
        &self,
        origin: &str,
        name: &str,
        record_type: DnsRecordType,
    ) -> Result<(), String> {
        // First try deleting the record
        match self.updater.delete(name, origin, record_type).await {
            Ok(_) => Ok(()),
            Err(err) => {
                trc::event!(
                    Dns(DnsEvent::RecordDeletionFailed),
                    Hostname = name.to_string(),
                    Reason = err.to_string(),
                    Details = origin.to_string(),
                    Type = record_type.as_str(),
                );
                Err(err.to_string())
            }
        }
    }
}

impl Server {
    pub async fn build_dns_updater_for_domain(
        &self,
        domain_id: Id,
    ) -> trc::Result<Result<DnsUpdater, String>> {
        if let Some(domain) = self.registry().object::<Domain>(domain_id).await? {
            match domain.dns_management {
                DnsManagement::Automatic(props) => {
                    self.build_dns_updater(props.dns_server_id).await
                }
                DnsManagement::Manual => Ok(Err(format!(
                    "Domain with ID {} is set to manual DNS management",
                    domain_id
                ))),
            }
        } else {
            Ok(Err(format!("Domain with ID {} not found", domain_id)))
        }
    }

    pub async fn build_dns_updater(
        &self,
        dns_server_id: Id,
    ) -> trc::Result<Result<DnsUpdater, String>> {
        if let Some(settings) = self.registry().object::<DnsServer>(dns_server_id).await? {
            Ok(DnsUpdater::build(settings, self.core.clone()).await)
        } else {
            Ok(Err(format!(
                "DNS server with ID {} not found",
                dns_server_id
            )))
        }
    }
}
