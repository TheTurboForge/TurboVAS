/* SPDX-FileCopyrightText: 2026 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import {OperatingSystemsCommand} from 'gmp/commands/os';
import {createEntitiesResponse, createHttp} from 'gmp/commands/testing';
import OperatingSystem from 'gmp/models/os';
import {createSession} from 'gmp/testing';

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('OperatingSystemsCommand tests', () => {
  test('should include assetType=os in exportByIds', async () => {
    const response = createEntitiesResponse('asset', []);
    const fakeHttp = createHttp(response);

    const cmd = new OperatingSystemsCommand(fakeHttp);

    const ids = ['123', '456'];
    const assetType = 'os';
    await cmd.exportByIds(ids, assetType);

    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        'bulk_selected:123': 1,
        'bulk_selected:456': 1,
        cmd: 'bulk_export',
        resource_type: 'asset',
        assetType: 'os',
        bulk_select: 1,
      },
    });
  });

  test('should include assetType=host in export of operating systems', async () => {
    const response = createEntitiesResponse('asset', []);
    const fakeHttp = createHttp(response);

    const cmd = new OperatingSystemsCommand(fakeHttp);

    const entities = [
      new OperatingSystem({id: '123'}),
      new OperatingSystem({id: '456'}),
    ];
    const assetType = 'os';
    await cmd.export(entities, assetType);

    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        'bulk_selected:123': 1,
        'bulk_selected:456': 1,
        cmd: 'bulk_export',
        resource_type: 'asset',
        assetType: 'os',
        bulk_select: 1,
      },
    });
  });

  test('should fetch operating systems through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 25, total: 1, sort: '-latest_severity', filter: 'linux'},
        items: [
          {
            id: 'os-1',
            name: 'cpe:/o:example:linux:1.0',
            title: 'Example Linux 1.0',
            latest_severity: 7.5,
            highest_severity: 9.1,
            average_severity: 4.25,
            hosts: 2,
            all_hosts: 3,
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
      path => `https://turbovas.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    fakeHttp.session.jwt = 'jwt-token';

    const cmd = new OperatingSystemsCommand(fakeHttp);
    const result = await cmd.get({filter: 'first=1 rows=25 search=linux'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(result.data[0].id).toEqual('os-1');
    expect(result.data[0].title).toEqual('Example Linux 1.0');
    expect(result.data[0].latestSeverity).toEqual(7.5);
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/operating-systems', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: 'latest_severity',
      filter: 'linux',
    });
  });
});
