/* SPDX-FileCopyrightText: 2026 TurboVAS contributors
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {useCallback, useEffect, useMemo, useState} from 'react';
import type {Scope, ScopeReport} from 'gmp/commands/scopes';
import {TASK_STATUS} from 'gmp/models/task';
import SeverityBar from 'web/components/bar/SeverityBar';
import StatusBar from 'web/components/bar/StatusBar';
import Button from 'web/components/form/Button';
import TextField from 'web/components/form/TextField';
import Column from 'web/components/layout/Column';
import PageTitle from 'web/components/layout/PageTitle';
import Link from 'web/components/link/Link';
import Section from 'web/components/section/Section';
import Table from 'web/components/table/StripedTable';
import TableBody from 'web/components/table/TableBody';
import TableData from 'web/components/table/TableData';
import TableHead from 'web/components/table/TableHead';
import TableRow from 'web/components/table/TableRow';
import useGmp from 'web/hooks/useGmp';
import useTranslation from 'web/hooks/useTranslation';
import {
  EmptyRow,
  ErrorMessage,
  formatDate,
  PageActions,
} from 'web/pages/scopes/common';
import SortDirection, {type SortDirectionType} from 'web/utils/sort-direction';

const PAGE_SIZE = 25;

type ScopeReportSortField =
  | 'created'
  | 'status'
  | 'scope'
  | 'latest_evidence'
  | 'severity'
  | 'high'
  | 'medium'
  | 'low'
  | 'log'
  | 'false_positive'
  | 'source_reports'
  | 'hosts'
  | 'results'
  | 'vulnerabilities';

const textValue = (value?: string) => value?.toLocaleLowerCase() ?? '';

const reportSearchText = (report: ScopeReport) =>
  [
    report.name,
    report.id,
    report.scopeName,
    report.scopeId,
    report.created,
    report.latestEvidenceTime,
  ]
    .filter(Boolean)
    .join(' ')
    .toLocaleLowerCase();

const reportSortValue = (
  report: ScopeReport,
  sortBy: ScopeReportSortField,
): string | number => {
  switch (sortBy) {
    case 'created':
      return report.created ?? '';
    case 'status':
      return TASK_STATUS.done;
    case 'scope':
      return textValue(report.scopeName);
    case 'latest_evidence':
      return report.latestEvidenceTime ?? '';
    case 'severity':
      return report.maxSeverity;
    case 'high':
      return report.severityHigh;
    case 'medium':
      return report.severityMedium;
    case 'low':
      return report.severityLow;
    case 'log':
      return report.severityLog;
    case 'false_positive':
      return report.severityFalsePositive;
    case 'source_reports':
      return report.sourceReportCount;
    case 'hosts':
      return report.hostsWithEvidence / Math.max(report.hostsTotal, 1);
    case 'results':
      return report.resultsTotal;
    case 'vulnerabilities':
      return report.vulnerabilitiesTotal;
    default:
      return '';
  }
};

const compareReports = (
  left: ScopeReport,
  right: ScopeReport,
  sortBy: ScopeReportSortField,
  sortDir: SortDirectionType,
) => {
  const leftValue = reportSortValue(left, sortBy);
  const rightValue = reportSortValue(right, sortBy);
  const direction = sortDir === SortDirection.ASC ? 1 : -1;

  if (typeof leftValue === 'number' && typeof rightValue === 'number') {
    return (leftValue - rightValue) * direction;
  }
  return String(leftValue).localeCompare(String(rightValue)) * direction;
};

const ScopeReportListPage = () => {
  const [_] = useTranslation();
  const gmp = useGmp();
  const [reports, setReports] = useState<ScopeReport[]>([]);
  const [scopes, setScopes] = useState<Scope[]>([]);
  const [filterText, setFilterText] = useState('');
  const [page, setPage] = useState(1);
  const [sortBy, setSortBy] = useState<ScopeReportSortField>('created');
  const [sortDir, setSortDir] = useState<SortDirectionType>(SortDirection.DESC);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string>();

  const organizationScope = useMemo(
    () => scopes.find(scope => scope.global || scope.name === 'Organization'),
    [scopes],
  );

  const loadReports = useCallback(async () => {
    setLoading(true);
    setError(undefined);
    try {
      const [scopeResponse, reportResponse] = await Promise.all([
        gmp.scopes.get({details: 0}),
        gmp.scopereports.get({details: 1}),
      ]);
      setScopes(scopeResponse.data);
      setReports(reportResponse.data);
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  }, [gmp]);

  useEffect(() => {
    void loadReports();
  }, [loadReports]);

  const filteredReports = useMemo(() => {
    const normalizedFilter = filterText.trim().toLocaleLowerCase();
    const matchingReports = normalizedFilter
      ? reports.filter(report => reportSearchText(report).includes(normalizedFilter))
      : reports;
    return [...matchingReports].sort((left, right) =>
      compareReports(left, right, sortBy, sortDir),
    );
  }, [filterText, reports, sortBy, sortDir]);

  const pageCount = Math.max(1, Math.ceil(filteredReports.length / PAGE_SIZE));
  const currentPage = Math.min(page, pageCount);
  const pageReports = filteredReports.slice(
    (currentPage - 1) * PAGE_SIZE,
    currentPage * PAGE_SIZE,
  );

  useEffect(() => {
    if (page > pageCount) {
      setPage(pageCount);
    }
  }, [page, pageCount]);

  const handleFilterChange = useCallback((value: string) => {
    setFilterText(value);
    setPage(1);
  }, []);

  const handleSortChange = useCallback(
    (newSortBy: string) => {
      const typedSortBy = newSortBy as ScopeReportSortField;
      if (typedSortBy === sortBy) {
        setSortDir(
          sortDir === SortDirection.ASC ? SortDirection.DESC : SortDirection.ASC,
        );
      } else {
        setSortBy(typedSortBy);
        setSortDir(SortDirection.ASC);
      }
      setPage(1);
    },
    [sortBy, sortDir],
  );

  const generateOrganizationReport = useCallback(async () => {
    if (!organizationScope) {
      return;
    }
    setLoading(true);
    setError(undefined);
    try {
      await gmp.scopes.generateReport({id: organizationScope.id});
      await loadReports();
    } catch (err) {
      setError(String(err));
      setLoading(false);
    }
  }, [gmp, loadReports, organizationScope]);

  return (
    <Column>
      <PageTitle title={_('Scope Reports')} />
      <Section title={_('Scope Reports')} />
      <PageActions>
        <TextField
          grow={1}
          placeholder={_('Filter scope reports')}
          title={_('Filter')}
          value={filterText}
          onChange={handleFilterChange}
        />
        <Button
          disabled={loading || !organizationScope}
          title={_('Generate Organization Report')}
          onClick={() => void generateOrganizationReport()}
        />
        <Button
          disabled={loading}
          title={_('Reload')}
          onClick={() => void loadReports()}
        />
        <Link to="/scopes">{_('Scopes')}</Link>
      </PageActions>
      <PageActions>
        <Button
          disabled={currentPage <= 1}
          title={_('Previous')}
          onClick={() => setPage(currentPage - 1)}
        />
        <span>
          {_('Page {{page}} of {{pages}}', {
            page: currentPage,
            pages: pageCount,
          })}{' '}
          ({filteredReports.length})
        </span>
        <Button
          disabled={currentPage >= pageCount}
          title={_('Next')}
          onClick={() => setPage(currentPage + 1)}
        />
      </PageActions>
      {error && <ErrorMessage>{error}</ErrorMessage>}
      <Table>
        <TableBody>
          <TableRow>
            <TableHead
              currentSortBy={sortBy}
              currentSortDir={sortDir}
              sortBy="created"
              title={_('Date')}
              onSortChange={handleSortChange}
            />
            <TableHead
              currentSortBy={sortBy}
              currentSortDir={sortDir}
              sortBy="status"
              title={_('Status')}
              onSortChange={handleSortChange}
            />
            <TableHead
              currentSortBy={sortBy}
              currentSortDir={sortDir}
              sortBy="scope"
              title={_('Scope')}
              onSortChange={handleSortChange}
            />
            <TableHead
              currentSortBy={sortBy}
              currentSortDir={sortDir}
              sortBy="latest_evidence"
              title={_('Latest Evidence')}
              onSortChange={handleSortChange}
            />
            <TableHead
              currentSortBy={sortBy}
              currentSortDir={sortDir}
              sortBy="severity"
              title={_('Severity')}
              onSortChange={handleSortChange}
            />
            <TableHead
              currentSortBy={sortBy}
              currentSortDir={sortDir}
              sortBy="high"
              title={_('High')}
              onSortChange={handleSortChange}
            />
            <TableHead
              currentSortBy={sortBy}
              currentSortDir={sortDir}
              sortBy="medium"
              title={_('Medium')}
              onSortChange={handleSortChange}
            />
            <TableHead
              currentSortBy={sortBy}
              currentSortDir={sortDir}
              sortBy="low"
              title={_('Low')}
              onSortChange={handleSortChange}
            />
            <TableHead
              currentSortBy={sortBy}
              currentSortDir={sortDir}
              sortBy="log"
              title={_('Log')}
              onSortChange={handleSortChange}
            />
            <TableHead
              currentSortBy={sortBy}
              currentSortDir={sortDir}
              sortBy="false_positive"
              title={_('False Positive')}
              onSortChange={handleSortChange}
            />
            <TableHead
              currentSortBy={sortBy}
              currentSortDir={sortDir}
              sortBy="source_reports"
              title={_('Source Reports')}
              onSortChange={handleSortChange}
            />
            <TableHead
              currentSortBy={sortBy}
              currentSortDir={sortDir}
              sortBy="hosts"
              title={_('Hosts')}
              onSortChange={handleSortChange}
            />
            <TableHead
              currentSortBy={sortBy}
              currentSortDir={sortDir}
              sortBy="results"
              title={_('Results')}
              onSortChange={handleSortChange}
            />
            <TableHead
              currentSortBy={sortBy}
              currentSortDir={sortDir}
              sortBy="vulnerabilities"
              title={_('Vulnerabilities')}
              onSortChange={handleSortChange}
            />
          </TableRow>
          {pageReports.length === 0 && <EmptyRow colSpan={14} />}
          {pageReports.map(report => (
            <TableRow key={report.id}>
              <TableData>
                <Link to={`/scopes/${report.scopeId}/reports/${report.id}`}>
                  {formatDate(report.created)}
                </Link>
              </TableData>
              <TableData>
                <StatusBar status={TASK_STATUS.done} />
              </TableData>
              <TableData>
                <Link to={`/scopes/${report.scopeId}`}>{report.scopeName}</Link>
              </TableData>
              <TableData>{formatDate(report.latestEvidenceTime)}</TableData>
              <TableData>
                <SeverityBar severity={report.maxSeverity} />
              </TableData>
              <TableData align="end">{report.severityHigh}</TableData>
              <TableData align="end">{report.severityMedium}</TableData>
              <TableData align="end">{report.severityLow}</TableData>
              <TableData align="end">{report.severityLog}</TableData>
              <TableData align="end">{report.severityFalsePositive}</TableData>
              <TableData>{report.sourceReportCount}</TableData>
              <TableData>
                {report.hostsWithEvidence}/{report.hostsTotal}
              </TableData>
              <TableData>{report.resultsTotal}</TableData>
              <TableData>{report.vulnerabilitiesTotal}</TableData>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </Column>
  );
};

export default ScopeReportListPage;
