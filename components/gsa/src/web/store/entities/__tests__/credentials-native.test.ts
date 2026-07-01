/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, expect, test, testing} from '@gsa/testing';
import {
  fetchNativeCredential,
  fetchNativeCredentials,
} from 'gmp/native-api/credentials';

const createGmp = ({jwt, token = 'test-token'}: {jwt?: string; token?: string} = {}) => ({
  buildUrl: testing.fn((path: string) => `https://turbovas.example/${path}`),
  session: {jwt, token},
});

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('native API credentials', () => {
  test('fetches redacted credential metadata as inherited Credential models', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 25, total: 1, sort: 'name', filter: ''},
        items: [
          {
            id: 'df6f4d9d-cd6a-4ed2-a9cd-22564fbb87b1',
            name: 'metasploitable',
            comment: 'SSH login credential',
            owner: 'admin',
            credential_type: 'up',
            allow_insecure: false,
            target_count: 1,
            scanner_count: 0,
            created_at: '2026-07-01T00:00:00Z',
            modified_at: '2026-07-01T00:01:00Z',
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({jwt: 'jwt-token'});

    const response = await fetchNativeCredentials(gmp, {
      page: 1,
      pageSize: 25,
      sort: 'name',
      filter: '',
    });

    const credential = response.credentials[0];
    expect(response.counts.filtered).toEqual(1);
    expect(credential.id).toEqual('df6f4d9d-cd6a-4ed2-a9cd-22564fbb87b1');
    expect(credential.name).toEqual('metasploitable');
    expect(credential.comment).toEqual('SSH login credential');
    expect(credential.owner?.name).toEqual('admin');
    expect(credential.credentialType).toEqual('up');
    expect(credential.login).toBeUndefined();
    expect(credential.credentialStore).toBeUndefined();
    expect(credential.privateKeyInfo).toBeUndefined();
    expect(credential.isInUse()).toEqual(true);
    expect(credential.userCapabilities.mayEdit('credential')).toEqual(true);
    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/credentials', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: 'name',
      filter: '',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/credentials',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
  });

  test('fetches redacted credential detail backlinks without secret fields', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: 'df6f4d9d-cd6a-4ed2-a9cd-22564fbb87b1',
        name: 'metasploitable',
        owner: 'admin',
        credential_type: 'up',
        target_count: 1,
        scanner_count: 1,
        targets: [
          {
            id: '9c7781dd-25e5-4f70-8b3d-a6b9180a0001',
            name: 'metasploitable target',
            use_type: 'ssh',
            port: 22,
          },
        ],
        scanners: [
          {
            id: '08b69003-5fc2-4037-a479-93b440211c73',
            name: 'OpenVAS Default',
            use_type: 'scanner',
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({jwt: 'jwt-token'});

    const credential = await fetchNativeCredential(
      gmp,
      'df6f4d9d-cd6a-4ed2-a9cd-22564fbb87b1',
    );

    expect(credential.targets).toHaveLength(1);
    expect(credential.targets[0].id).toEqual(
      '9c7781dd-25e5-4f70-8b3d-a6b9180a0001',
    );
    expect(credential.targets[0].name).toEqual('metasploitable target');
    expect(credential.scanners).toHaveLength(1);
    expect(credential.scanners[0].name).toEqual('OpenVAS Default');
    expect(credential.login).toBeUndefined();
    expect(credential.privateKeyInfo).toBeUndefined();
    expect(credential.publicKeyInfo).toBeUndefined();
    expect(credential.credentialStore).toBeUndefined();
  });
});
