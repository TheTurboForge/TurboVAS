/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import {ReportConfigsCommand} from 'gmp/commands/report-configs';
import {createHttp, createEntitiesResponse} from 'gmp/commands/testing';
import {ALL_FILTER} from 'gmp/models/filter';
import {createSession} from 'gmp/testing';

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('ReportConfigsCommand tests', () => {
  test('should return all report configs', async () => {
    const response = createEntitiesResponse('report_config', [
      {
        _id: '1',
      },
      {
        _id: '2',
      },
    ]);

    const fakeHttp = createHttp(response);
    const cmd = new ReportConfigsCommand(fakeHttp);
    const resp = await cmd.getAll();
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        cmd: 'get_report_configs',
        filter: ALL_FILTER.toFilterString(),
      },
    });
    const {data} = resp;
    expect(data.length).toEqual(2);
  });

  test('should return report configs', async () => {
    const response = createEntitiesResponse('report_config', [
      {
        _id: '1',
      },
      {
        _id: '2',
      },
    ]);

    const fakeHttp = createHttp(response);

    expect.hasAssertions();

    const cmd = new ReportConfigsCommand(fakeHttp);
    const resp = await cmd.get();
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        cmd: 'get_report_configs',
      },
    });
    const {data} = resp;
    expect(data.length).toEqual(2);
  });

  test('should return filtered report configs', async () => {
    const response = createEntitiesResponse('report_config', [
      {
        _id: '1',
      },
      {
        _id: '2',
      },
    ]);

    const fakeHttp = createHttp(response);
    const cmd = new ReportConfigsCommand(fakeHttp);
    const resp = await cmd.get({filter: 'test filter'});
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        cmd: 'get_report_configs',
        filter: 'test filter',
      },
    });
    const {data} = resp;
    expect(data.length).toEqual(2);
  });

  test('should fetch report configs through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 25, total: 1, sort: 'name', filter: 'pdf'},
        items: [
          {
            id: 'b7d16778-fb49-4e96-a1d0-5efbc2150f03',
            name: 'PDF Report',
            comment: 'Native metadata',
            owner: {name: 'admin'},
            report_format: {
              id: 'c402cc3e-b531-11e1-9163-406186ea4fc5',
              name: 'PDF',
            },
            writable: true,
            in_use: false,
            orphan: false,
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(undefined) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => `https://turbovas.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    fakeHttp.session.jwt = 'jwt-token';

    const cmd = new ReportConfigsCommand(fakeHttp);
    const result = await cmd.get({filter: 'first=1 rows=25 search=pdf'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(result.data[0].id).toEqual('b7d16778-fb49-4e96-a1d0-5efbc2150f03');
    expect(result.data[0].name).toEqual('PDF Report');
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/report-configs', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: 'name',
      filter: 'pdf',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/report-configs',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
  });
});
