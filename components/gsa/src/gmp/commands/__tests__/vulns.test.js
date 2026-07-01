/* SPDX-FileCopyrightText: 2026 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import {
  createAggregatesResponse,
  createEntitiesResponse,
  createHttp,
} from 'gmp/commands/testing';
import {createSession} from 'gmp/testing';
import {VulnerabilitiesCommand} from 'gmp/commands/vulns';

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('VulnerabilitiesCommand tests', () => {
  test('should parse get_vulns response', async () => {
    const response = createEntitiesResponse(
      'vuln',
      [{id: 'v1'}, {id: 'v2'}],
      {
        getName: 'get_vulns',
        responseName: 'get_vulns_response',
        pluralName: 'vulns',
        countName: 'vuln_count',
      },
    );
    const fakeHttp = createHttp(response);
    const cmd = new VulnerabilitiesCommand(fakeHttp);

    const result = await cmd.get();

    expect(result.data).toHaveLength(2);
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {cmd: 'get_vulns'},
    });
  });

  test('should fetch vulnerabilities through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 25, total: 1, sort: '-severity', filter: 'postgres'},
        items: [
          {
            id: '1.3.6.1.4.1.25623.1.0.900001',
            name: 'PostgreSQL vulnerability',
            family: 'General',
            severity: 7.5,
            qod: 80,
            result_count: 3,
            host_count: 2,
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
    const cmd = new VulnerabilitiesCommand(fakeHttp);

    const result = await cmd.get({filter: 'first=1 rows=25 search=postgres'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(result.data[0].id).toEqual('1.3.6.1.4.1.25623.1.0.900001');
    expect(result.data[0].family).toEqual('General');
    expect(result.data[0].severity).toEqual(7.5);
    expect(result.data[0].results.count).toEqual(3);
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/vulnerabilities', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: 'severity',
      filter: 'postgres',
    });
  });

  test('should request severity aggregates for vulnerabilities', async () => {
    const response = createAggregatesResponse();
    const fakeHttp = createHttp(response);
    const cmd = new VulnerabilitiesCommand(fakeHttp);

    await cmd.getSeverityAggregates({filter: 'first=1'});

    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        aggregate_type: 'vuln',
        cmd: 'get_aggregate',
        filter: 'first=1',
        group_column: 'severity',
      },
    });
  });
});
