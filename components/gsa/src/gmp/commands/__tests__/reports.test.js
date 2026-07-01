/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import ReportsCommand from 'gmp/commands/reports';
import {createHttp, createEntitiesResponse} from 'gmp/commands/testing';
import {createSession} from 'gmp/testing';
import {ALL_FILTER} from 'gmp/models/filter';

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('ReportsCommand tests', () => {
  test('should return all reports', async () => {
    const response = createEntitiesResponse('report', [
      {
        _id: '1',
      },
      {
        _id: '2',
      },
    ]);
    const fakeHttp = createHttp(response);
    const cmd = new ReportsCommand(fakeHttp);
    const resp = await cmd.getAll();
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        cmd: 'get_reports',
        details: 0,
        filter: ALL_FILTER.toFilterString(),
        usage_type: 'scan',
      },
    });
    const {data} = resp;
    expect(data.length).toEqual(2);
  });

  test('should return results', async () => {
    const response = createEntitiesResponse('report', [
      {
        _id: '1',
      },
      {
        _id: '2',
      },
    ]);
    const fakeHttp = createHttp(response);
    const cmd = new ReportsCommand(fakeHttp);
    const resp = await cmd.get();
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        cmd: 'get_reports',
        details: 0,
        usage_type: 'scan',
      },
    });
    const {data} = resp;
    expect(data.length).toEqual(2);
  });

  test('should fetch reports through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {
          page: 1,
          page_size: 25,
          total: 1,
          sort: '-creation_time',
          filter: 'done',
        },
        items: [
          {
            id: 'report-1',
            name: 'Native report',
            status: 'Done',
            creation_time: '2026-06-14T06:27:42Z',
            result_count: 7,
            vulnerability_count: 3,
            host_count: 1,
            max_severity: 8.2,
            severity: {
              critical: 1,
              high: 2,
              medium: 3,
              low: 1,
              log: 0,
              false_positive: 0,
            },
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(undefined);
    fakeHttp.buildUrl = testing.fn(
      path => `https://turbovas.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    fakeHttp.session.jwt = 'jwt-token';
    const cmd = new ReportsCommand(fakeHttp);

    const result = await cmd.get({filter: 'first=1 rows=25 search=done'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(result.data[0].id).toEqual('report-1');
    expect(result.data[0].name).toEqual('Native report');
    expect(result.meta.counts.filtered).toEqual(1);
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/reports', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: 'creation_time',
      filter: 'done',
    });
  });
});
