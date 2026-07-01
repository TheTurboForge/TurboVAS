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
import {type XmlResponseData} from 'gmp/http/transform/fast-xml';
import type {Element} from 'gmp/models/model';
import ReportConfig from 'gmp/models/report-config';
import {
  fetchNativeReportConfigs,
  nativeReportConfigsQueryFromFilter,
} from 'gmp/native-api/report-configs';

interface ReportConfigsResponseData extends XmlResponseData {
  get_report_configs?: {
    get_report_configs_response?: Element;
  };
}

export class ReportConfigsCommand extends EntitiesCommand<ReportConfig> {
  constructor(http: Http) {
    super(http, 'report_config', ReportConfig);
  }

  getEntitiesResponse(root: XmlResponseData) {
    return (
      (root as ReportConfigsResponseData).get_report_configs
        ?.get_report_configs_response ?? {}
    );
  }

  async get(params: HttpCommandInputParams = {}, options?: HttpCommandOptions) {
    if (!canUseNativeApi(this.http)) {
      return super.get(params, options);
    }

    const filter = filterFromCommandParams(params);
    const nativeResponse = await fetchNativeReportConfigs(
      this.http,
      nativeReportConfigsQueryFromFilter(filter),
    );
    return new Response(nativeResponse.reportConfigs, {
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
    const reportConfigs: ReportConfig[] = [];
    let total = Number.POSITIVE_INFINITY;

    for (let page = 1; reportConfigs.length < total; page += 1) {
      const nativeResponse = await fetchNativeReportConfigs(this.http, {
        ...nativeReportConfigsQueryFromFilter(filter),
        page,
        pageSize: NATIVE_COMMAND_PAGE_SIZE,
      });
      reportConfigs.push(...nativeResponse.reportConfigs);
      total = nativeResponse.page.total;
      if (nativeResponse.reportConfigs.length === 0) {
        break;
      }
    }

    return new Response(
      reportConfigs,
      nativeCollectionMeta(
        filter,
        reportConfigs,
        Number.isFinite(total) ? total : 0,
      ),
    );
  }
}

export default ReportConfigsCommand;
