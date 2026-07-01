/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import EntitiesCommand from 'gmp/commands/entities';
import type {
  HttpCommandInputParams,
  HttpCommandOptions,
} from 'gmp/commands/http';
import {
  canUseNativeApi,
  filterFromCommandParams,
  nativeCollectionMeta,
  NATIVE_COMMAND_PAGE_SIZE,
} from 'gmp/commands/native';
import type Http from 'gmp/http/http';
import Response from 'gmp/http/response';
import Alert from 'gmp/models/alert';
import {type Element} from 'gmp/models/model';
import {
  fetchNativeAlerts,
  nativeAlertsQueryFromFilter,
} from 'gmp/native-api/alerts';

class AlertsCommand extends EntitiesCommand<Alert> {
  constructor(http: Http) {
    super(http, 'alert', Alert);
  }

  getEntitiesResponse(root: Element): Element {
    // @ts-expect-error
    return root.get_alerts.get_alerts_response;
  }

  async get(params: HttpCommandInputParams = {}, options?: HttpCommandOptions) {
    if (!canUseNativeApi(this.http)) {
      return super.get(params, options);
    }

    const filter = filterFromCommandParams(params);
    const nativeResponse = await fetchNativeAlerts(
      this.http,
      nativeAlertsQueryFromFilter(filter),
    );
    return new Response(nativeResponse.alerts, {
      filter,
      counts: nativeResponse.counts,
    });
  }

  async getAll(
    params: HttpCommandInputParams = {},
    options?: HttpCommandOptions,
  ) {
    if (!canUseNativeApi(this.http)) {
      return super.getAll(params, options);
    }

    const filter = filterFromCommandParams(params).all();
    const alerts: Alert[] = [];
    let total = Number.POSITIVE_INFINITY;

    for (let page = 1; alerts.length < total; page += 1) {
      const nativeResponse = await fetchNativeAlerts(this.http, {
        ...nativeAlertsQueryFromFilter(filter),
        page,
        pageSize: NATIVE_COMMAND_PAGE_SIZE,
      });
      alerts.push(...nativeResponse.alerts);
      total = nativeResponse.page.total;
      if (nativeResponse.alerts.length === 0) {
        break;
      }
    }

    return new Response(
      alerts,
      nativeCollectionMeta(filter, alerts, Number.isFinite(total) ? total : 0),
    );
  }
}

export default AlertsCommand;
