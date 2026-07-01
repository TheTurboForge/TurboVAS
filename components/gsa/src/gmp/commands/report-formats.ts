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
import ReportFormat from 'gmp/models/report-format';
import {
  fetchNativeReportFormats,
  nativeReportFormatsQueryFromFilter,
} from 'gmp/native-api/report-formats';

interface ReportFormatsResponseData extends XmlResponseData {
  get_report_formats?: {
    get_report_formats_response?: Element;
  };
}

export class ReportFormatsCommand extends EntitiesCommand<ReportFormat> {
  constructor(http: Http) {
    super(http, 'report_format', ReportFormat);
  }

  getEntitiesResponse(root: XmlResponseData) {
    return (
      (root as ReportFormatsResponseData).get_report_formats
        ?.get_report_formats_response ?? {}
    );
  }

  async get(params: HttpCommandInputParams = {}, options?: HttpCommandOptions) {
    if (!canUseNativeApi(this.http)) {
      return super.get(params, options);
    }

    const filter = filterFromCommandParams(params);
    const nativeResponse = await fetchNativeReportFormats(
      this.http,
      nativeReportFormatsQueryFromFilter(filter),
    );
    return new Response(nativeResponse.reportFormats, {
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
    const reportFormats: ReportFormat[] = [];
    let total = Number.POSITIVE_INFINITY;

    for (let page = 1; reportFormats.length < total; page += 1) {
      const nativeResponse = await fetchNativeReportFormats(this.http, {
        ...nativeReportFormatsQueryFromFilter(filter),
        page,
        pageSize: NATIVE_COMMAND_PAGE_SIZE,
      });
      reportFormats.push(...nativeResponse.reportFormats);
      total = nativeResponse.page.total;
      if (nativeResponse.reportFormats.length === 0) {
        break;
      }
    }

    return new Response(
      reportFormats,
      nativeCollectionMeta(
        filter,
        reportFormats,
        Number.isFinite(total) ? total : 0,
      ),
    );
  }
}

export default ReportFormatsCommand;
