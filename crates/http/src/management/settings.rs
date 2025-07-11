/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use directory::Permission;
use hyper::Method;
use serde_json::json;
use store::ahash::AHashMap;
use utils::{config::ConfigKey, map::vec_map::VecMap, url_params::UrlParams};

use http_proto::{request::decode_path_element, *};
use std::future::Future;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "camelCase")]
pub enum UpdateSettings {
    Delete {
        keys: Vec<String>,
    },
    Clear {
        prefix: String,
        #[serde(default)]
        filter: Option<String>,
    },
    Insert {
        prefix: Option<String>,
        values: Vec<(String, String)>,
        assert_empty: bool,
    },
}

pub trait ManageSettings: Sync + Send {
    fn handle_manage_settings(
        &self,
        req: &HttpRequest,
        path: Vec<&str>,
        body: Option<Vec<u8>>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;
}

impl ManageSettings for Server {
    async fn handle_manage_settings(
        &self,
        req: &HttpRequest,
        path: Vec<&str>,
        body: Option<Vec<u8>>,
        access_token: &AccessToken,
    ) -> trc::Result<HttpResponse> {
        match (path.get(1).copied(), req.method()) {
            (Some("group"), &Method::GET) => {
                // Validate the access token
                access_token.assert_has_permission(Permission::SettingsList)?;

                // List settings
                let params = UrlParams::new(req.uri().query());
                let prefix = params
                    .get("prefix")
                    .map(|p| {
                        if !p.ends_with('.') {
                            format!("{p}.")
                        } else {
                            p.to_string()
                        }
                    })
                    .unwrap_or_default();
                let suffix = params
                    .get("suffix")
                    .map(|s| {
                        if !s.starts_with('.') {
                            format!(".{s}")
                        } else {
                            s.to_string()
                        }
                    })
                    .unwrap_or_default();
                let field = params.get("field");
                let filter = params.get("filter").unwrap_or_default().to_lowercase();
                let limit: usize = params.parse("limit").unwrap_or(0);
                let mut offset =
                    params.parse::<usize>("page").unwrap_or(0).saturating_sub(1) * limit;
                let has_filter = !filter.is_empty();

                let settings = self.core.storage.config.list(&prefix, true).await?;
                if !suffix.is_empty() && !settings.is_empty() {
                    // Obtain record ids
                    let mut total = 0;
                    let mut ids = Vec::new();
                    for key in settings.keys() {
                        if let Some(id) = key.strip_suffix(&suffix) {
                            if !id.is_empty() {
                                if !has_filter {
                                    if offset == 0 {
                                        if limit == 0 || ids.len() < limit {
                                            ids.push(id);
                                        }
                                    } else {
                                        offset -= 1;
                                    }
                                    total += 1;
                                } else {
                                    ids.push(id);
                                }
                            }
                        }
                    }

                    // Group settings by record id
                    let mut records = Vec::new();
                    for id in ids {
                        let mut record = AHashMap::new();
                        let prefix = format!("{id}.");
                        record.insert("_id".to_string(), id.to_string());
                        for (k, v) in &settings {
                            if let Some(k) = k.strip_prefix(&prefix) {
                                if field.is_none_or(|field| field == k) {
                                    record.insert(k.to_string(), v.to_string());
                                }
                            } else if record.len() > 1 {
                                break;
                            }
                        }

                        if has_filter {
                            if record
                                .iter()
                                .any(|(_, v)| v.to_lowercase().contains(&filter))
                            {
                                if offset == 0 {
                                    if limit == 0 || records.len() < limit {
                                        records.push(record);
                                    }
                                } else {
                                    offset -= 1;
                                }
                                total += 1;
                            }
                        } else {
                            records.push(record);
                        }
                    }

                    Ok(JsonResponse::new(json!({
                        "data": {
                            "total": total,
                            "items": records,
                        },
                    }))
                    .into_http_response())
                } else {
                    let mut total = 0;
                    let mut items = Vec::new();

                    for (k, v) in settings {
                        if filter.is_empty()
                            || k.to_lowercase().contains(&filter)
                            || v.to_lowercase().contains(&filter)
                        {
                            if offset == 0 {
                                if limit == 0 || items.len() < limit {
                                    let k =
                                        k.strip_prefix(&prefix).map(|k| k.to_string()).unwrap_or(k);
                                    items.push(json!({
                                        "_id": k,
                                        "_value": v,
                                    }));
                                }
                            } else {
                                offset -= 1;
                            }
                            total += 1;
                        }
                    }

                    Ok(JsonResponse::new(json!({
                        "data": {
                            "total": total,
                            "items": items,
                        },
                    }))
                    .into_http_response())
                }
            }
            (Some("list"), &Method::GET) => {
                // Validate the access token
                access_token.assert_has_permission(Permission::SettingsList)?;

                // List settings
                let params = UrlParams::new(req.uri().query());
                let prefix = params
                    .get("prefix")
                    .map(|p| {
                        if !p.ends_with('.') {
                            format!("{p}.")
                        } else {
                            p.to_string()
                        }
                    })
                    .unwrap_or_default();
                let limit: usize = params.parse("limit").unwrap_or(0);
                let offset = params.parse::<usize>("page").unwrap_or(0).saturating_sub(1) * limit;

                let settings = self.core.storage.config.list(&prefix, true).await?;
                let total = settings.len();
                let items = settings
                    .into_iter()
                    .skip(offset)
                    .take(if limit == 0 { total } else { limit })
                    .collect::<VecMap<_, _>>();

                Ok(JsonResponse::new(json!({
                    "data": {
                        "total": total,
                        "items": items,
                    },
                }))
                .into_http_response())
            }
            (Some("keys"), &Method::GET) => {
                // Validate the access token
                access_token.assert_has_permission(Permission::SettingsList)?;

                // Obtain keys
                let params = UrlParams::new(req.uri().query());
                let keys = params
                    .get("keys")
                    .map(|s| s.split(',').collect::<Vec<_>>())
                    .unwrap_or_default();
                let prefixes = params
                    .get("prefixes")
                    .map(|s| s.split(',').collect::<Vec<_>>())
                    .unwrap_or_default();
                let mut results = AHashMap::with_capacity(keys.len());

                for key in keys {
                    if let Some(value) = self.core.storage.config.get(key).await? {
                        results.insert(key.to_string(), value);
                    }
                }
                for prefix in prefixes {
                    let prefix = if !prefix.ends_with('.') {
                        format!("{prefix}.")
                    } else {
                        prefix.to_string()
                    };
                    results.extend(self.core.storage.config.list(&prefix, false).await?);
                }

                Ok(JsonResponse::new(json!({
                    "data": results,
                }))
                .into_http_response())
            }
            (Some(prefix), &Method::DELETE) if !prefix.is_empty() => {
                // Validate the access token
                access_token.assert_has_permission(Permission::SettingsDelete)?;

                let prefix = decode_path_element(prefix);

                self.core.storage.config.clear(prefix.as_ref()).await?;

                Ok(JsonResponse::new(json!({
                    "data": (),
                }))
                .into_http_response())
            }
            (None, &Method::POST) => {
                // Validate the access token
                access_token.assert_has_permission(Permission::SettingsUpdate)?;

                let changes = serde_json::from_slice::<Vec<UpdateSettings>>(
                    body.as_deref().unwrap_or_default(),
                )
                .map_err(|err| {
                    trc::EventType::Resource(trc::ResourceEvent::BadParameters).from_json_error(err)
                })?;

                for change in changes {
                    match change {
                        UpdateSettings::Delete { keys } => {
                            for key in keys {
                                self.core.storage.config.clear(key).await?;
                            }
                        }
                        UpdateSettings::Clear { prefix, filter } => {
                            if let Some(filter) = filter {
                                for (key, value) in
                                    self.core.storage.config.list(&prefix, false).await?
                                {
                                    if value.to_lowercase().contains(&filter)
                                        || key.to_lowercase().contains(&filter)
                                    {
                                        self.core.storage.config.clear(key).await?;
                                    }
                                }
                            } else {
                                self.core.storage.config.clear_prefix(&prefix).await?;
                            }
                        }
                        UpdateSettings::Insert {
                            prefix,
                            values,
                            assert_empty,
                        } => {
                            if assert_empty {
                                if let Some(prefix) = &prefix {
                                    if !self
                                        .core
                                        .storage
                                        .config
                                        .list(&format!("{prefix}."), true)
                                        .await?
                                        .is_empty()
                                    {
                                        return Err(trc::ManageEvent::AssertFailed.into_err());
                                    }
                                } else if let Some((key, _)) = values.first() {
                                    if self.core.storage.config.get(key).await?.is_some() {
                                        return Err(trc::ManageEvent::AssertFailed.into_err());
                                    }
                                }
                            }

                            self.core
                                .storage
                                .config
                                .set(
                                    values.into_iter().map(|(key, value)| ConfigKey {
                                        key: if let Some(prefix) = &prefix {
                                            format!("{prefix}.{key}")
                                        } else {
                                            key
                                        },
                                        value,
                                    }),
                                    true,
                                )
                                .await?;
                        }
                    }
                }

                Ok(JsonResponse::new(json!({
                    "data": (),
                }))
                .into_http_response())
            }
            _ => Err(trc::ResourceEvent::NotFound.into_err()),
        }
    }
}
