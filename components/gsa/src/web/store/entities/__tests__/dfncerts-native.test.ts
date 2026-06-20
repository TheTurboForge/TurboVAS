/* SPDX-FileCopyrightText: 2026 TurboVAS contributors
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, expect, test, testing} from '@gsa/testing';
import {fetchNativeDfnCertAdvisories} from 'gmp/native-api/dfn-cert-advisories';

const createGmp = ({
  jwt,
  token = 'test-token',
}: {jwt?: string; token?: string} = {}) => ({
  buildUrl: testing.fn((path: string) => `https://turbovas.example/${path}`),
  session: {jwt, token},
});

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('native API DFN-CERT advisory catalog', () => {
  test('fetches top-level DFN-CERT advisories as inherited models', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {
          page: 1,
          page_size: 25,
          total: 1,
          sort: '-created',
          filter: 'openssl',
        },
        items: [
          {
            id: 'dfn-uuid-1',
            name: 'DFN-CERT-2026-001',
            comment: 'operator note',
            title: 'Example DFN-CERT advisory',
            summary: 'OpenSSL update advisory.',
            severity: 8.7,
            cve_refs: 2,
            cves: ['CVE-2026-10001', 'CVE-2026-10002'],
            created_at: '2026-06-18T20:00:00Z',
            modified_at: '2026-06-19T07:00:00Z',
            updated_at: '2026-06-19T07:00:00Z',
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({jwt: 'jwt-token'});

    const response = await fetchNativeDfnCertAdvisories(gmp, {
      page: 1,
      pageSize: 25,
      sort: '-created',
      filter: 'openssl',
    });

    const advisory = response.dfncerts[0];
    expect(response.counts.filtered).toEqual(1);
    expect(advisory.id).toEqual('dfn-uuid-1');
    expect(advisory.name).toEqual('DFN-CERT-2026-001');
    expect(advisory.comment).toEqual('operator note');
    expect(advisory.title).toEqual('Example DFN-CERT advisory');
    expect(advisory.summary).toEqual('OpenSSL update advisory.');
    expect(advisory.severity).toEqual(8.7);
    expect(advisory.cve_refs).toEqual(2);
    expect(advisory.cves).toEqual(['CVE-2026-10001', 'CVE-2026-10002']);
    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/dfn-cert-advisories', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: '-created',
      filter: 'openssl',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/dfn-cert-advisories',
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
