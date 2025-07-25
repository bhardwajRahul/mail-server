/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::JmapMethods;
use common::Server;
use directory::QueryParams;
use http_proto::HttpSessionData;
use jmap_proto::{
    method::query::{Filter, QueryRequest, QueryResponse, RequestArguments},
    types::{collection::Collection, state::State},
};
use std::future::Future;
use store::{query::ResultSet, roaring::RoaringBitmap};

pub trait PrincipalQuery: Sync + Send {
    fn principal_query(
        &self,
        request: QueryRequest<RequestArguments>,
        session: &HttpSessionData,
    ) -> impl Future<Output = trc::Result<QueryResponse>> + Send;
}

impl PrincipalQuery for Server {
    async fn principal_query(
        &self,
        mut request: QueryRequest<RequestArguments>,
        session: &HttpSessionData,
    ) -> trc::Result<QueryResponse> {
        let account_id = request.account_id.document_id();
        let mut result_set = ResultSet {
            account_id,
            collection: Collection::Principal.into(),
            results: RoaringBitmap::new(),
        };
        let mut is_set = true;

        for cond in std::mem::take(&mut request.filter) {
            match cond {
                Filter::Name(name) => {
                    if let Some(principal) = self
                        .core
                        .storage
                        .directory
                        .query(QueryParams::name(name.as_str()).with_return_member_of(false))
                        .await?
                    {
                        if is_set || result_set.results.contains(principal.id()) {
                            result_set.results =
                                RoaringBitmap::from_sorted_iter([principal.id()]).unwrap();
                        } else {
                            result_set.results = RoaringBitmap::new();
                        }
                    } else {
                        result_set.results = RoaringBitmap::new();
                    }
                    is_set = false;
                }
                Filter::Email(email) => {
                    let mut ids = RoaringBitmap::new();
                    if let Some(id) = self
                        .email_to_id(&self.core.storage.directory, &email, session.session_id)
                        .await?
                    {
                        ids.insert(id);
                    }
                    if is_set {
                        result_set.results = ids;
                        is_set = false;
                    } else {
                        result_set.results &= ids;
                    }
                }
                Filter::Type(_) => {}
                other => {
                    return Err(trc::JmapEvent::UnsupportedFilter
                        .into_err()
                        .details(other.to_string()));
                }
            }
        }

        if is_set {
            result_set.results = self
                .get_document_ids(u32::MAX, Collection::Principal)
                .await?
                .unwrap_or_default();
        }

        let (response, paginate) = self
            .build_query_response(&result_set, State::Initial, &request)
            .await?;

        if let Some(paginate) = paginate {
            self.sort(result_set, Vec::new(), paginate, response).await
        } else {
            Ok(response)
        }
    }
}
