/* SPDX-FileCopyrightText: 2026 TurboVAS contributors
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import CollectionCounts from 'gmp/collection/collection-counts';
import type Filter from 'gmp/models/filter';
import Report from 'gmp/models/report';
import type {UrlParams} from 'gmp/http/utils';

interface NativeApiSession {
  readonly jwt?: string;
  readonly token?: string;
}

interface NativeApiGmp {
  readonly session: NativeApiSession;
  buildUrl(path: string, params?: UrlParams): string;
}

interface NativeReportReference {
  id: string;
  name: string;
}

interface NativeReportSeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  log: number;
  false_positive: number;
}

interface NativeReportItem {
  id: string;
  name: string;
  status: string;
  task?: NativeReportReference;
  target?: NativeReportReference;
  scan_start?: string;
  scan_end?: string;
  creation_time?: string;
  modification_time?: string;
  result_count: number;
  vulnerability_count: number;
  host_count: number;
  cve_count: number;
  severity: NativeReportSeverityCounts;
  max_severity: number;
}

interface NativeReportPage {
  page: number;
  page_size: number;
  total: number;
  sort: string;
  filter: string;
}

interface NativeReportCollectionPayload {
  page?: Partial<NativeReportPage>;
  items?: NativeReportItem[];
}

type NativeReportDetailPayload = NativeReportItem;

export interface NativeReportQuery {
  page: number;
  pageSize: number;
  sort: string;
  filter: string;
}

export interface NativeReportsResponse {
  reports: Report[];
  counts: CollectionCounts;
  page: NativeReportPage;
}

export interface NativeReportResponse {
  report: Report;
}

const REPORT_SORT_FIELDS: Record<string, string> = {
  date: 'creation_time',
  creation_time: 'creation_time',
  status: 'status',
  task: 'task',
  target: 'target',
  severity: 'severity',
  result_count: 'result_count',
  vulnerability_count: 'vulnerability_count',
  host_count: 'host_count',
  cve_count: 'cve_count',
  critical: 'critical',
  high: 'high',
  medium: 'medium',
  low: 'low',
  log: 'log',
  false_positive: 'false_positive',
};

const integerValue = (value: unknown, fallback = 0): number => {
  const parsed = Number.parseInt(String(value ?? fallback), 10);
  return Number.isFinite(parsed) ? parsed : fallback;
};

const stringValue = (value: unknown): string =>
  typeof value === 'string' ? value : '';

const nativeSortFromFilter = (filter?: Filter): string => {
  const reverse = filter?.get('sort-reverse');
  const ascending = filter?.get('sort');
  const rawField = stringValue(reverse ?? ascending) || 'creation_time';
  const nativeField = REPORT_SORT_FIELDS[rawField] ?? rawField;
  return reverse !== undefined ? `-${nativeField}` : nativeField;
};

const nativeSearchFromFilter = (filter?: Filter): string => {
  const search = filter?.get('search');
  if (search !== undefined) {
    return String(search);
  }
  const criteria = filter?.toFilterCriteriaString().trim() ?? '';
  return /[=<>:~]/.test(criteria) ? '' : criteria;
};

export const nativeReportQueryFromFilter = (filter?: Filter): NativeReportQuery => {
  const pageSize = Math.max(1, integerValue(filter?.get('rows'), 25));
  const first = Math.max(1, integerValue(filter?.get('first'), 1));
  return {
    page: Math.floor((first - 1) / pageSize) + 1,
    pageSize,
    sort: nativeSortFromFilter(filter),
    filter: nativeSearchFromFilter(filter),
  };
};

const nativeCounts = (page: NativeReportPage, length: number) =>
  new CollectionCounts({
    first: page.total > 0 ? (page.page - 1) * page.page_size + 1 : 0,
    all: page.total,
    filtered: page.total,
    length,
    rows: page.page_size,
  });

const resultCountElement = (count: number) => ({filtered: count, full: count});

export const nativeReportToModel = (item: NativeReportItem): Report => {
  const task = item.task
    ? {
        _id: item.task.id,
        name: item.task.name,
        progress: item.status === 'Done' ? 100 : undefined,
        target: item.target
          ? {
              _id: item.target.id,
              name: item.target.name,
            }
          : undefined,
      }
    : undefined;

  const timestamp = item.creation_time ?? item.scan_end ?? item.scan_start;
  const severity = resultCountElement(item.max_severity);
  return Report.fromElement({
    _id: item.id,
    name: item.name,
    creation_time: item.creation_time,
    modification_time: item.modification_time,
    task: item.task
      ? {
          _id: item.task.id,
          name: item.task.name,
        }
      : undefined,
    report: {
      _id: item.id,
      _type: 'scan',
      timestamp,
      scan_start: item.scan_start,
      scan_end: item.scan_end,
      scan_run_status: item.status,
      severity,
      task,
      hosts: {count: item.host_count},
      vulns: {count: item.vulnerability_count},
      result_count: {
        filtered: item.result_count,
        full: item.result_count,
        critical: resultCountElement(item.severity.critical),
        high: resultCountElement(item.severity.high),
        medium: resultCountElement(item.severity.medium),
        low: resultCountElement(item.severity.low),
        log: resultCountElement(item.severity.log),
        false_positive: resultCountElement(item.severity.false_positive),
      },
      timezone: 'UTC',
      timezone_abbrev: 'UTC',
    },
  });
};

const nativeHeaders = (gmp: NativeApiGmp): HeadersInit => {
  const headers: HeadersInit = {Accept: 'application/json'};
  if (gmp.session.jwt) {
    headers.Authorization = `Bearer ${gmp.session.jwt}`;
  }
  return headers;
};

const fetchNativeJson = async <T>(
  gmp: NativeApiGmp,
  path: string,
  params: UrlParams,
): Promise<T> => {
  const response = await fetch(gmp.buildUrl(path, params), {
    credentials: 'include',
    headers: nativeHeaders(gmp),
  });
  if (!response.ok) {
    throw new Error(`Native API request failed with status ${response.status}`);
  }
  return (await response.json()) as T;
};

export const fetchNativeReport = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<NativeReportResponse> => {
  const payload = await fetchNativeJson<NativeReportDetailPayload>(
    gmp,
    `api/v1/reports/${encodeURIComponent(id)}`,
    {token: gmp.session.token},
  );
  return {report: nativeReportToModel(payload)};
};

export const fetchNativeReports = async (
  gmp: NativeApiGmp,
  query: NativeReportQuery,
): Promise<NativeReportsResponse> => {
  const payload = await fetchNativeJson<NativeReportCollectionPayload>(
    gmp,
    'api/v1/reports',
    {
      token: gmp.session.token,
      page: query.page,
      page_size: query.pageSize,
      sort: query.sort,
      filter: query.filter,
    },
  );
  const page = {
    page: integerValue(payload.page?.page, 1),
    page_size: integerValue(payload.page?.page_size, query.pageSize),
    total: integerValue(payload.page?.total),
    sort: stringValue(payload.page?.sort),
    filter: stringValue(payload.page?.filter),
  };
  const reports = (payload.items ?? []).map(nativeReportToModel);
  return {
    reports,
    counts: nativeCounts(page, reports.length),
    page,
  };
};
