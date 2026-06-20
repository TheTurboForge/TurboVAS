/* SPDX-FileCopyrightText: 2026 TurboVAS contributors
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, expect, test, testing} from '@gsa/testing';
import {fetchNativeScanConfigs} from 'gmp/native-api/scan-configs';

const createGmp = ({jwt, token = 'test-token'}: {jwt?: string; token?: string} = {}) => ({
  buildUrl: testing.fn((path: string) => `https://turbovas.example/${path}`),
  session: {jwt, token},
});

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('native API scan configs', () => {
  test('fetches scan configs as inherited ScanConfig models', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 25, total: 1, sort: 'name', filter: ''},
        items: [
          {
            id: 'daba56c8-73ec-11df-a475-002264764cea',
            name: 'Full and fast',
            comment: 'Default scanner config',
            owner: {name: 'admin'},
            family_count: 33,
            families_growing: 1,
            nvt_count: 177000,
            nvts_growing: 1,
            predefined: true,
            deprecated: false,
            writable: false,
            in_use: true,
            usage_type: 'scan',
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({jwt: 'jwt-token'});

    const response = await fetchNativeScanConfigs(gmp, {
      page: 1,
      pageSize: 25,
      sort: 'families_total',
      filter: '',
      predefined: '1',
    });

    const config = response.scanConfigs[0];
    expect(response.counts.filtered).toEqual(1);
    expect(config.id).toEqual('daba56c8-73ec-11df-a475-002264764cea');
    expect(config.name).toEqual('Full and fast');
    expect(config.owner?.name).toEqual('admin');
    expect(config.families?.count).toEqual(33);
    expect(config.families?.trend).toEqual(1);
    expect(config.nvts?.count).toEqual(177000);
    expect(config.predefined).toEqual(true);
    expect(config.isWritable()).toEqual(false);
    expect(config.isInUse()).toEqual(true);
    expect(config.tasks).toEqual([]);
    expect(config.userCapabilities.mayEdit('config')).toEqual(true);
    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/scan-configs', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: 'families_total',
      filter: '',
      predefined: '1',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/scan-configs',
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
