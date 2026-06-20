/* SPDX-FileCopyrightText: 2026 TurboVAS contributors
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, expect, test, testing} from '@gsa/testing';
import {fetchNativeTag, fetchNativeTags} from 'gmp/native-api/tags';

const createGmp = ({jwt, token = 'test-token'}: {jwt?: string; token?: string} = {}) => ({
  buildUrl: testing.fn((path: string) => `https://turbovas.example/${path}`),
  session: {jwt, token},
});

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('native API tags', () => {
  test('fetches tags as inherited Tag models', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 25, total: 1, sort: 'name', filter: ''},
        items: [
          {
            id: '6d4dddf0-92a4-427f-b65d-bb9f9627aa01',
            name: 'Environment',
            comment: 'Operator label',
            owner: {name: 'admin'},
            resource_type: 'task',
            resource_count: 3,
            active: true,
            value: 'production',
            writable: true,
            permissions: ['get_tags', 'modify_tag'],
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({jwt: 'jwt-token'});

    const response = await fetchNativeTags(gmp, {
      page: 1,
      pageSize: 25,
      sort: 'name',
      filter: '',
      active: '1',
      resourceType: 'task',
      value: 'prod',
    });

    const tag = response.tags[0];
    expect(response.counts.filtered).toEqual(1);
    expect(tag.id).toEqual('6d4dddf0-92a4-427f-b65d-bb9f9627aa01');
    expect(tag.name).toEqual('Environment');
    expect(tag.comment).toEqual('Operator label');
    expect(tag.owner?.name).toEqual('admin');
    expect(tag.resourceType).toEqual('task');
    expect(tag.resourceCount).toEqual(3);
    expect(tag.value).toEqual('production');
    expect(tag.isActive()).toEqual(true);
    expect(tag.userCapabilities.mayEdit('tag')).toEqual(true);
    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/tags', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: 'name',
      filter: '',
      active: '1',
      resource_type: 'task',
      value: 'prod',
    });
    expect(fetchMock).toHaveBeenCalledWith('https://turbovas.example/api/v1/tags', {
      credentials: 'include',
      headers: {
        Accept: 'application/json',
        Authorization: 'Bearer jwt-token',
      },
    });
  });

  test('fetches tag detail metadata', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: '6d4dddf0-92a4-427f-b65d-bb9f9627aa01',
        name: 'Environment',
        resources: {type: 'target', count: {total: 1}},
        active: false,
        value: 'staging',
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({jwt: 'jwt-token'});

    const tag = await fetchNativeTag(
      gmp,
      '6d4dddf0-92a4-427f-b65d-bb9f9627aa01',
    );

    expect(tag.isActive()).toEqual(false);
    expect(tag.resourceType).toEqual('target');
    expect(tag.resourceCount).toEqual(1);
    expect(tag.value).toEqual('staging');
  });
});
