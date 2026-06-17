/* SPDX-FileCopyrightText: 2026 TurboVAS contributors
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type {UrlParams} from 'gmp/http/utils';

interface NativeApiSession {
  readonly jwt?: string;
  readonly token?: string;
}

interface NativeApiGmp {
  readonly session: NativeApiSession;
  buildUrl(path: string, params?: UrlParams): string;
}

export interface NativeCollectionPage {
  page: number;
  pageSize: number;
  total: number;
  sort: string;
  filter: string;
}

export interface NativeCollection<T> {
  page: NativeCollectionPage;
  items: T[];
}

export interface NativeCollectionQuery {
  page: number;
  pageSize: number;
  sort: string;
  filter?: string;
}

export interface ScopeReportHostItem {
  host: string;
  scopeMembership: string;
  sourceReportCount: number;
  resultCount: number;
  vulnerabilityCount: number;
  authenticatedScanState: string;
  sourceReportIds: string[];
}

export interface ScopeReportCveItem {
  id: string;
  affectedSystemCount: number;
  resultCount: number;
  maxSeverity: number;
  sourceReportIds: string[];
}

export interface ScopeReportErrorMessageItem {
  id: string;
  host: string;
  port: string;
  nvtOid: string;
  description: string;
  sourceReportId: string;
  createdAt?: string;
}

type NativeRecord = Record<string, unknown>;

const asRecord = (value: unknown): NativeRecord => {
  if (typeof value === 'object' && value !== null) {
    return value as NativeRecord;
  }
  return {};
};

const asArray = (value: unknown): NativeRecord[] => {
  return Array.isArray(value) ? value.map(asRecord) : [];
};

const stringValue = (value: unknown, fallback = ''): string => {
  return typeof value === 'string' ? value : fallback;
};

const optionalStringValue = (value: unknown): string | undefined => {
  return typeof value === 'string' && value.length > 0 ? value : undefined;
};

const numberValue = (value: unknown): number => {
  const parsed =
    typeof value === 'number' ? value : Number.parseFloat(String(value ?? 0));
  return Number.isFinite(parsed) ? parsed : 0;
};

const integerValue = (value: unknown): number => {
  const parsed =
    typeof value === 'number' ? value : Number.parseInt(String(value ?? 0), 10);
  return Number.isFinite(parsed) ? parsed : 0;
};

const stringArrayValue = (value: unknown): string[] => {
  return Array.isArray(value)
    ? value.filter(item => typeof item === 'string')
    : [];
};

const mapPage = (payload: NativeRecord): NativeCollectionPage => {
  const page = asRecord(payload.page);
  return {
    page: integerValue(page.page) || 1,
    pageSize: integerValue(page.page_size) || 25,
    total: integerValue(page.total),
    sort: stringValue(page.sort),
    filter: stringValue(page.filter),
  };
};

const fetchNativeCollection = async <T>(
  gmp: NativeApiGmp,
  path: string,
  query: NativeCollectionQuery,
  mapper: (item: NativeRecord) => T,
): Promise<NativeCollection<T>> => {
  const headers: HeadersInit = {Accept: 'application/json'};
  if (gmp.session.jwt) {
    headers.Authorization = `Bearer ${gmp.session.jwt}`;
  }

  const response = await fetch(
    gmp.buildUrl(path, {
      token: gmp.session.token,
      page: query.page,
      page_size: query.pageSize,
      sort: query.sort,
      filter: query.filter,
    }),
    {
      credentials: 'include',
      headers,
    },
  );
  if (!response.ok) {
    throw new Error(`Native API request failed with status ${response.status}`);
  }

  const payload = asRecord(await response.json());
  return {
    page: mapPage(payload),
    items: asArray(payload.items).map(mapper),
  };
};

const scopeReportPath = (
  scopeId: string,
  scopeReportId: string,
  collection: string,
) =>
  `api/v1/scopes/${encodeURIComponent(scopeId)}/reports/${encodeURIComponent(
    scopeReportId,
  )}/${collection}`;

export const fetchNativeScopeReportHosts = (
  gmp: NativeApiGmp,
  scopeId: string,
  scopeReportId: string,
  query: NativeCollectionQuery,
) =>
  fetchNativeCollection<ScopeReportHostItem>(
    gmp,
    scopeReportPath(scopeId, scopeReportId, 'hosts'),
    query,
    item => ({
      host: stringValue(item.host),
      scopeMembership: stringValue(item.scope_membership),
      sourceReportCount: integerValue(item.source_report_count),
      resultCount: integerValue(item.result_count),
      vulnerabilityCount: integerValue(item.vulnerability_count),
      authenticatedScanState: stringValue(item.authenticated_scan_state),
      sourceReportIds: stringArrayValue(item.source_report_ids),
    }),
  );

export const fetchNativeScopeReportCves = (
  gmp: NativeApiGmp,
  scopeId: string,
  scopeReportId: string,
  query: NativeCollectionQuery,
) =>
  fetchNativeCollection<ScopeReportCveItem>(
    gmp,
    scopeReportPath(scopeId, scopeReportId, 'cves'),
    query,
    item => ({
      id: stringValue(item.id),
      affectedSystemCount: integerValue(item.affected_system_count),
      resultCount: integerValue(item.result_count),
      maxSeverity: numberValue(item.max_severity),
      sourceReportIds: stringArrayValue(item.source_report_ids),
    }),
  );

export const fetchNativeScopeReportErrors = (
  gmp: NativeApiGmp,
  scopeId: string,
  scopeReportId: string,
  query: NativeCollectionQuery,
) =>
  fetchNativeCollection<ScopeReportErrorMessageItem>(
    gmp,
    scopeReportPath(scopeId, scopeReportId, 'errors'),
    query,
    item => ({
      id: stringValue(item.id),
      host: stringValue(item.host),
      port: stringValue(item.port),
      nvtOid: stringValue(item.nvt_oid),
      description: stringValue(item.description),
      sourceReportId: stringValue(item.source_report_id),
      createdAt: optionalStringValue(item.created_at),
    }),
  );
