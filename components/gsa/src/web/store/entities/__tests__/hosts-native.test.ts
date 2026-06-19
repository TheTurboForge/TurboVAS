/* SPDX-FileCopyrightText: 2026 TurboVAS contributors
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, expect, test, testing} from '@gsa/testing';
import {fetchNativeHosts} from 'gmp/native-api/hosts';

const createGmp = ({jwt, token = 'test-token'}: {jwt?: string; token?: string} = {}) => ({
  buildUrl: testing.fn((path: string) => `https://turbovas.example/${path}`),
  session: {jwt, token},
});

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('native API hosts list', () => {
  test('fetches top-level hosts as inherited Host models', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 25, total: 1, sort: '-severity', filter: ''},
        items: [
          {
            id: 'a4be8ecf-4f23-4c83-b0fd-3b65161d652b',
            name: '192.168.178.42',
            comment: 'operator workstation',
            hostname: 'workstation.local',
            ip: '192.168.178.42',
            best_os_cpe: 'cpe:/o:canonical:ubuntu_linux',
            best_os_txt: 'Ubuntu Linux',
            severity: 7.5,
            identifiers: [
              {
                id: 'identifier-ip',
                name: 'ip',
                value: '192.168.178.42',
                source_type: 'Report Host',
                source_id: 'report-1',
                source_data: 'Full and fast',
              },
              {
                id: 'identifier-hostname',
                name: 'hostname',
                value: 'workstation.local',
                source_type: 'Report Host',
                source_id: 'report-1',
                source_data: 'Full and fast',
              },
            ],
            created_at: '2026-06-18T18:00:00Z',
            modified_at: '2026-06-18T20:00:00Z',
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({jwt: 'jwt-token'});

    const response = await fetchNativeHosts(gmp, {
      page: 1,
      pageSize: 25,
      sort: '-severity',
      filter: '',
    });

    const host = response.hosts[0];
    expect(response.counts.filtered).toEqual(1);
    expect(host.id).toEqual('a4be8ecf-4f23-4c83-b0fd-3b65161d652b');
    expect(host.name).toEqual('192.168.178.42');
    expect(host.comment).toEqual('operator workstation');
    expect(host.hostname).toEqual('workstation.local');
    expect(host.ip).toEqual('192.168.178.42');
    expect(host.os).toEqual('cpe:/o:canonical:ubuntu_linux');
    expect(host.details?.best_os_txt?.value).toEqual('Ubuntu Linux');
    expect(host.severity).toEqual(7.5);
    expect(host.identifiers).toHaveLength(2);
    expect(host.identifiers[0].id).toEqual('identifier-ip');
    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/hosts', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: '-severity',
      filter: '',
    });
    expect(fetchMock).toHaveBeenCalledWith('https://turbovas.example/api/v1/hosts', {
      credentials: 'include',
      headers: {
        Accept: 'application/json',
        Authorization: 'Bearer jwt-token',
      },
    });
  });
});
