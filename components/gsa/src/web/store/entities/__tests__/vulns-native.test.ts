/* SPDX-FileCopyrightText: 2026 TurboVAS contributors
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, expect, test, testing} from '@gsa/testing';
import {fetchNativeVulnerabilities} from 'gmp/native-api/vulnerabilities';

const createGmp = ({jwt, token = 'test-token'}: {jwt?: string; token?: string} = {}) => ({
  buildUrl: testing.fn((path: string) => `https://turbovas.example/${path}`),
  session: {jwt, token},
});

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('native API vulnerabilities list', () => {
  test('fetches top-level vulnerabilities as inherited Vulnerability models', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 25, total: 1, sort: '-severity', filter: ''},
        items: [
          {
            id: '1.3.6.1.4.1.25623.1.0.900001',
            name: 'Example vulnerability',
            oldest_result: '2026-06-18T18:00:00Z',
            newest_result: '2026-06-18T20:00:00Z',
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
    const gmp = createGmp({jwt: 'jwt-token'});

    const response = await fetchNativeVulnerabilities(gmp, {
      page: 1,
      pageSize: 25,
      sort: '-severity',
      filter: '',
    });

    const vulnerability = response.vulnerabilities[0];
    expect(response.counts.filtered).toEqual(1);
    expect(vulnerability.id).toEqual('1.3.6.1.4.1.25623.1.0.900001');
    expect(vulnerability.name).toEqual('Example vulnerability');
    expect(vulnerability.severity).toEqual(7.5);
    expect(vulnerability.qod).toEqual(80);
    expect(vulnerability.results?.count).toEqual(3);
    expect(vulnerability.hosts?.count).toEqual(2);
    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/vulnerabilities', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: '-severity',
      filter: '',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/vulnerabilities',
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
