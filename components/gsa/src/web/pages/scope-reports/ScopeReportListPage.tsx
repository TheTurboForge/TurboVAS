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

const ScopeReportListPage = () => {
  const [_] = useTranslation();
  const gmp = useGmp();
  const [reports, setReports] = useState<ScopeReport[]>([]);
  const [scopes, setScopes] = useState<Scope[]>([]);
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
      {error && <ErrorMessage>{error}</ErrorMessage>}
      <Table>
        <TableBody>
          <TableRow>
            <TableHead>{_('Date')}</TableHead>
            <TableHead>{_('Status')}</TableHead>
            <TableHead>{_('Scope')}</TableHead>
            <TableHead>{_('Latest Evidence')}</TableHead>
            <TableHead>{_('Severity')}</TableHead>
            <TableHead>{_('High')}</TableHead>
            <TableHead>{_('Medium')}</TableHead>
            <TableHead>{_('Low')}</TableHead>
            <TableHead>{_('Log')}</TableHead>
            <TableHead>{_('False Positive')}</TableHead>
            <TableHead>{_('Source Reports')}</TableHead>
            <TableHead>{_('Hosts')}</TableHead>
            <TableHead>{_('Results')}</TableHead>
            <TableHead>{_('Vulnerabilities')}</TableHead>
          </TableRow>
          {reports.length === 0 && <EmptyRow colSpan={14} />}
          {reports.map(report => (
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
