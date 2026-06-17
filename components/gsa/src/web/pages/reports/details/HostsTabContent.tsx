/* SPDX-FileCopyrightText: 2026 Greenbone AG
 * Modified by TurboVAS contributors, 2026.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type Filter from 'gmp/models/filter';
import type {TaskStatus} from 'gmp/models/task';
import NativeHostsTab from 'web/pages/reports/details/NativeHostsTab';

export interface HostsTabContentProps {
  reportId: string;
  status: TaskStatus;
  reportFilter: Filter;
}

const HostsTabContent = ({
  reportId,
  reportFilter,
}: HostsTabContentProps) => (
  <NativeHostsTab reportFilter={reportFilter} reportId={reportId} />
);

export default HostsTabContent;
