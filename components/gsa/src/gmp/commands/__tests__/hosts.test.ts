/* SPDX-FileCopyrightText: 2026 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import {HostsCommand} from 'gmp/commands/hosts';
import {createEntitiesResponse, createHttp} from 'gmp/commands/testing';
import Host from 'gmp/models/host';
import {createSession} from 'gmp/testing';

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('HostsCommand tests', () => {
  test('should include assetType=host in exportByIds', async () => {
    const response = createEntitiesResponse('asset', []);
    const fakeHttp = createHttp(response);

    const cmd = new HostsCommand(fakeHttp);

    const ids = ['123', '456'];
    const assetType = 'host';

    await cmd.exportByIds(ids, assetType);

    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        'bulk_selected:123': 1,
        'bulk_selected:456': 1,
        cmd: 'bulk_export',
        resource_type: 'asset',
        assetType: 'host',
        bulk_select: 1,
      },
    });
  });

  test('should include assetType=host in export of hosts', async () => {
    const response = createEntitiesResponse('asset', []);
    const fakeHttp = createHttp(response);

    const cmd = new HostsCommand(fakeHttp);

    const entities = [new Host({id: '123'}), new Host({id: '456'})];
    const assetType = 'host';

    await cmd.export(entities, assetType);

    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        'bulk_selected:123': 1,
        'bulk_selected:456': 1,
        cmd: 'bulk_export',
        resource_type: 'asset',
        assetType: 'host',
        bulk_select: 1,
      },
    });
  });

  test('should fetch hosts through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 25, total: 1, sort: '-severity', filter: 'web'},
        items: [
          {
            id: 'host-1',
            name: '192.0.2.10',
            hostname: 'web.example.test',
            ip: '192.0.2.10',
            best_os_cpe: 'cpe:/o:example:linux',
            severity: 7.5,
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

    const cmd = new HostsCommand(fakeHttp);
    const result = await cmd.get({filter: 'first=1 rows=25 search=web'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(result.data[0].id).toEqual('host-1');
    expect(result.data[0].severity).toEqual(7.5);
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/hosts', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: 'severity',
      filter: 'web',
    });
  });
});
