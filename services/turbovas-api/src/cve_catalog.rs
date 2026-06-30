// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Json,
    extract::{Path, State},
};
use serde::Serialize;
use tokio_postgres::{Client, Row};

use crate::{
    app_state::AppState,
    collections::{CVE_CATALOG_DEFAULT_SORT, CVE_CATALOG_SORT_FIELDS},
    errors::ApiError,
    formatters::unix_ts_to_rfc3339,
    path_ids::validate_cve_id,
    query::{ApiQuery, Collection, CollectionQuery, normalize_collection_query, sort_clause},
    user_tags::{ReportUserTag, catalog_user_tags},
};

#[derive(Debug, Serialize)]
struct CatalogEpssItem {
    score: f64,
    percentile: f64,
}

#[derive(Debug, Serialize)]
pub(crate) struct CatalogCveCertReference {
    pub(crate) name: String,
    pub(crate) title: String,
    #[serde(rename = "type")]
    pub(crate) cert_type: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct CatalogCveNvtReference {
    pub(crate) id: String,
    pub(crate) name: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct CatalogCveReference {
    pub(crate) url: String,
    pub(crate) tags: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct CatalogCveMatchedCpe {
    #[serde(rename = "_id")]
    pub(crate) id: String,
    pub(crate) deprecated: i32,
}

#[derive(Debug, Serialize)]
pub(crate) struct CatalogCveMatchedCpes {
    pub(crate) cpe: Vec<CatalogCveMatchedCpe>,
}

#[derive(Debug, Serialize)]
pub(crate) struct CatalogCveMatchString {
    pub(crate) criteria: String,
    pub(crate) vulnerable: i32,
    pub(crate) status: String,
    pub(crate) version_start_including: String,
    pub(crate) version_start_excluding: String,
    pub(crate) version_end_including: String,
    pub(crate) version_end_excluding: String,
    pub(crate) matched_cpes: CatalogCveMatchedCpes,
}

#[derive(Debug, Serialize)]
pub(crate) struct CatalogCveConfigurationNode {
    pub(crate) operator: String,
    pub(crate) negate: i32,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) match_string: Vec<CatalogCveMatchString>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) node: Vec<CatalogCveConfigurationNode>,
}

#[derive(Debug, Serialize)]
pub(crate) struct CatalogCveConfigurationNodes {
    pub(crate) node: Vec<CatalogCveConfigurationNode>,
}

#[derive(Debug, Serialize)]
pub(crate) struct CatalogCveItem {
    id: String,
    name: String,
    comment: String,
    description: String,
    cvss_base_vector: String,
    severity: f64,
    products: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) cert_refs: Vec<CatalogCveCertReference>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) nvt_refs: Vec<CatalogCveNvtReference>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) references: Vec<CatalogCveReference>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) configuration_nodes: Option<CatalogCveConfigurationNodes>,
    #[serde(skip_serializing_if = "Option::is_none")]
    epss: Option<CatalogEpssItem>,
    published_at: Option<String>,
    modified_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct CatalogCveDetail {
    #[serde(flatten)]
    pub(crate) item: CatalogCveItem,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) user_tags: Vec<ReportUserTag>,
}

pub(crate) async fn cve_catalog(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<CatalogCveItem>>, ApiError> {
    let params = normalize_collection_query(query, CVE_CATALOG_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, CVE_CATALOG_SORT_FIELDS)?;
    let sql = format!(
        r#"WITH cve_rows AS (
             SELECT c.name AS id,
                    c.name AS name,
                    coalesce(c.comment, '') AS comment,
                    coalesce(c.description, '') AS description,
                    coalesce(c.cvss_vector, '') AS cvss_base_vector,
                    coalesce(c.severity, 0)::double precision AS severity,
                    coalesce(c.products, '') AS products,
                    e.epss::double precision AS epss_score,
                    e.percentile::double precision AS epss_percentile,
                    coalesce(c.creation_time, 0)::bigint AS published_at_unix,
                    coalesce(c.modification_time, 0)::bigint AS modified_at_unix
               FROM scap.cves c
               LEFT JOIN scap.epss_scores e ON e.cve = c.name
         ),
         filtered AS (
             SELECT * FROM cve_rows
              WHERE ($1 = ''
                     OR lower(id) LIKE '%' || lower($1) || '%'
                     OR lower(description) LIKE '%' || lower($1) || '%'
                     OR lower(cvss_base_vector) LIKE '%' || lower($1) || '%'
                     OR lower(products) LIKE '%' || lower($1) || '%')
         )
         SELECT count(*) OVER()::bigint AS total, * FROM filtered
          ORDER BY {sort_sql}, id ASC LIMIT $2 OFFSET $3;"#,
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(&sql, &[&params.filter, &params.page_size, &params.offset])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "CVE catalog list query failed");
            ApiError::Database
        })?;
    let total = rows
        .first()
        .map(|row| row.get::<_, i64>("total"))
        .unwrap_or(0);
    let items = rows.iter().map(catalog_cve_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

pub(crate) async fn cve_catalog_detail(
    State(state): State<AppState>,
    Path(cve_id): Path<String>,
) -> Result<Json<CatalogCveDetail>, ApiError> {
    validate_cve_id(&cve_id)?;
    let sql = r#"SELECT c.name AS id,
                        c.id AS internal_id,
                        c.name AS name,
                        coalesce(c.comment, '') AS comment,
                        coalesce(c.description, '') AS description,
                        coalesce(c.cvss_vector, '') AS cvss_base_vector,
                        coalesce(c.severity, 0)::double precision AS severity,
                        coalesce(c.products, '') AS products,
                        e.epss::double precision AS epss_score,
                        e.percentile::double precision AS epss_percentile,
                        coalesce(c.creation_time, 0)::bigint AS published_at_unix,
                        coalesce(c.modification_time, 0)::bigint AS modified_at_unix
                   FROM scap.cves c
                   LEFT JOIN scap.epss_scores e ON e.cve = c.name
                  WHERE lower(c.name) = lower($1)
                  LIMIT 1;"#;
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let row = client
        .query_opt(sql, &[&cve_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "CVE catalog detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    let cve_internal_id: i32 = row.get("internal_id");
    let mut item = catalog_cve_from_row(&row);
    item.cert_refs = cve_cert_refs(&client, &cve_id).await?;
    item.nvt_refs = cve_nvt_refs(&client, &cve_id).await?;
    item.references = cve_references(&client, cve_internal_id).await?;
    item.configuration_nodes = cve_configuration_nodes(&client, cve_internal_id).await?;
    let user_tags = catalog_user_tags(&client, "cve", &cve_id).await?;
    Ok(Json(CatalogCveDetail { item, user_tags }))
}

async fn cve_configuration_nodes(
    client: &Client,
    cve_internal_id: i32,
) -> Result<Option<CatalogCveConfigurationNodes>, ApiError> {
    let root_rows = client
        .query(
            r#"SELECT DISTINCT root_id::integer AS root_id
                 FROM scap.cpe_match_nodes
                WHERE cve_id = $1
                  AND root_id <> 0
                ORDER BY root_id ASC;"#,
            &[&cve_internal_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "CVE catalog configuration root query failed");
            ApiError::Database
        })?;

    let mut nodes = Vec::new();
    for root_row in root_rows {
        let root_id: i32 = root_row.get("root_id");
        let mut node = cve_configuration_node(client, root_id).await?;
        let child_rows = client
            .query(
                r#"SELECT id::integer AS id
                     FROM scap.cpe_match_nodes
                    WHERE root_id = $1
                      AND root_id <> id
                    ORDER BY id ASC;"#,
                &[&root_id],
            )
            .await
            .map_err(|error| {
                tracing::warn!(%error, "CVE catalog configuration child query failed");
                ApiError::Database
            })?;
        for child_row in child_rows {
            let child_id: i32 = child_row.get("id");
            node.node
                .push(cve_configuration_node(client, child_id).await?);
        }
        nodes.push(node);
    }

    if nodes.is_empty() {
        Ok(None)
    } else {
        Ok(Some(CatalogCveConfigurationNodes { node: nodes }))
    }
}

async fn cve_configuration_node(
    client: &Client,
    node_id: i32,
) -> Result<CatalogCveConfigurationNode, ApiError> {
    let row = client
        .query_opt(
            r#"SELECT coalesce(operator, '') AS operator,
                      coalesce(negate, 0)::integer AS negate
                 FROM scap.cpe_match_nodes
                WHERE id = $1;"#,
            &[&node_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "CVE catalog configuration node query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::Database)?;

    Ok(CatalogCveConfigurationNode {
        operator: row.get("operator"),
        negate: row.get("negate"),
        match_string: cve_match_strings(client, node_id).await?,
        node: Vec::new(),
    })
}

async fn cve_match_strings(
    client: &Client,
    node_id: i32,
) -> Result<Vec<CatalogCveMatchString>, ApiError> {
    let rows = client
        .query(
            r#"SELECT coalesce(n.vulnerable, 0)::integer AS vulnerable,
                      coalesce(r.criteria, '') AS criteria,
                      coalesce(r.match_criteria_id, '') AS match_criteria_id,
                      coalesce(r.status, '') AS status,
                      coalesce(r.version_start_incl, '') AS version_start_incl,
                      coalesce(r.version_start_excl, '') AS version_start_excl,
                      coalesce(r.version_end_incl, '') AS version_end_incl,
                      coalesce(r.version_end_excl, '') AS version_end_excl
                 FROM scap.cpe_match_strings r
                 JOIN scap.cpe_nodes_match_criteria n
                   ON r.match_criteria_id = n.match_criteria_id
                WHERE n.node_id = $1
                ORDER BY r.criteria ASC, r.match_criteria_id ASC;"#,
            &[&node_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "CVE catalog configuration match-string query failed");
            ApiError::Database
        })?;

    let mut match_strings = Vec::new();
    for row in rows {
        let match_criteria_id: String = row.get("match_criteria_id");
        match_strings.push(CatalogCveMatchString {
            criteria: row.get("criteria"),
            vulnerable: row.get("vulnerable"),
            status: row.get("status"),
            version_start_including: row.get("version_start_incl"),
            version_start_excluding: row.get("version_start_excl"),
            version_end_including: row.get("version_end_incl"),
            version_end_excluding: row.get("version_end_excl"),
            matched_cpes: cve_matched_cpes(client, &match_criteria_id).await?,
        });
    }
    Ok(match_strings)
}

async fn cve_matched_cpes(
    client: &Client,
    match_criteria_id: &str,
) -> Result<CatalogCveMatchedCpes, ApiError> {
    let rows = client
        .query(
            r#"SELECT coalesce(m.cpe_name, '') AS id,
                      coalesce(c.deprecated, 0)::integer AS deprecated
                 FROM scap.cpe_matches m
                 LEFT JOIN scap.cpes c ON c.cpe_name_id = m.cpe_name_id
                WHERE m.match_criteria_id = $1
                ORDER BY m.cpe_name ASC;"#,
            &[&match_criteria_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "CVE catalog matched CPE query failed");
            ApiError::Database
        })?;

    Ok(CatalogCveMatchedCpes {
        cpe: rows
            .iter()
            .map(|row| CatalogCveMatchedCpe {
                id: row.get("id"),
                deprecated: row.get("deprecated"),
            })
            .collect(),
    })
}

async fn cve_references(
    client: &Client,
    cve_internal_id: i32,
) -> Result<Vec<CatalogCveReference>, ApiError> {
    let rows = client
        .query(
            r#"SELECT coalesce(url, '') AS url,
                      coalesce(tags, ARRAY[]::text[]) AS tags
                 FROM scap.cve_references
                WHERE cve_id = $1
                ORDER BY url ASC;"#,
            &[&cve_internal_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "CVE catalog reference query failed");
            ApiError::Database
        })?;
    Ok(rows
        .iter()
        .map(|row| CatalogCveReference {
            url: row.get("url"),
            tags: row.get("tags"),
        })
        .collect())
}

async fn cve_cert_refs(
    client: &Client,
    cve_id: &str,
) -> Result<Vec<CatalogCveCertReference>, ApiError> {
    let rows = client
        .query(
            r#"SELECT *
                 FROM (
                       SELECT 'CERT-Bund'::text AS cert_type,
                              d.name AS name,
                              coalesce(d.title, '') AS title
                         FROM cert.cert_bund_cves dc
                         JOIN cert.cert_bund_advs d ON d.id = dc.adv_id
                        WHERE lower(dc.cve_name) = lower($1)
                        UNION ALL
                       SELECT 'DFN-CERT'::text AS cert_type,
                              d.name AS name,
                              coalesce(d.title, '') AS title
                         FROM cert.dfn_cert_cves dc
                         JOIN cert.dfn_cert_advs d ON d.id = dc.adv_id
                        WHERE lower(dc.cve_name) = lower($1)
                      ) refs
                ORDER BY cert_type ASC, name ASC;"#,
            &[&cve_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "CVE catalog CERT reference query failed");
            ApiError::Database
        })?;
    Ok(rows
        .iter()
        .map(|row| CatalogCveCertReference {
            cert_type: row.get("cert_type"),
            name: row.get("name"),
            title: row.get("title"),
        })
        .collect())
}

async fn cve_nvt_refs(
    client: &Client,
    cve_id: &str,
) -> Result<Vec<CatalogCveNvtReference>, ApiError> {
    let rows = client
        .query(
            r#"SELECT DISTINCT n.oid AS id,
                              coalesce(nullif(n.name, ''), n.oid) AS name
                 FROM vt_refs vr
                 JOIN nvts n ON n.oid = vr.vt_oid
                WHERE lower(vr.ref_id) = lower($1)
                  AND lower(vr.type) IN ('cve', 'cve_id')
                ORDER BY name ASC, id ASC;"#,
            &[&cve_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "CVE catalog NVT reference query failed");
            ApiError::Database
        })?;
    Ok(rows
        .iter()
        .map(|row| CatalogCveNvtReference {
            id: row.get("id"),
            name: row.get("name"),
        })
        .collect())
}

fn split_catalog_products(value: String) -> Vec<String> {
    value
        .split_whitespace()
        .filter(|product| !product.is_empty())
        .map(ToString::to_string)
        .collect()
}

pub(crate) fn catalog_cve_from_row(row: &Row) -> CatalogCveItem {
    let epss_score: Option<f64> = row.get("epss_score");
    let epss_percentile: Option<f64> = row.get("epss_percentile");
    CatalogCveItem {
        id: row.get("id"),
        name: row.get("name"),
        comment: row.get("comment"),
        description: row.get("description"),
        cvss_base_vector: row.get("cvss_base_vector"),
        severity: row.get("severity"),
        products: split_catalog_products(row.get("products")),
        cert_refs: Vec::new(),
        nvt_refs: Vec::new(),
        references: Vec::new(),
        configuration_nodes: None,
        epss: epss_score
            .zip(epss_percentile)
            .map(|(score, percentile)| CatalogEpssItem { score, percentile }),
        published_at: unix_ts_to_rfc3339(row.get("published_at_unix")),
        modified_at: unix_ts_to_rfc3339(row.get("modified_at_unix")),
    }
}
