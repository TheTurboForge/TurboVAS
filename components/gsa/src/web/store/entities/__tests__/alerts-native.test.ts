/* SPDX-FileCopyrightText: 2026 TurboVAS contributors
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, expect, test, testing} from '@gsa/testing';
import {
  fetchNativeAlerts,
  nativeAlertsQueryFromFilter,
} from 'gmp/native-api/alerts';
import Filter from 'gmp/models/filter';
import {loadEntities} from 'web/store/entities/alerts';
import {createState} from 'web/store/entities/utils/testing';
import {filterIdentifier} from 'web/store/utils';

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

describe('native API alerts', () => {
  test('fetches redacted alert list metadata as inherited Alert models', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {
          page: 2,
          page_size: 10,
          total: 11,
          sort: '-event',
          filter: 'secops',
        },
        items: [
          {
            id: '4e110580-5281-4e8e-bbc5-322f3ef8d9e8',
            name: 'Notify SecOps',
            comment: 'Native metadata only',
            owner: {name: 'admin'},
            active: true,
            in_use: true,
            task_count: 2,
            event: {type: 'Task run status changed'},
            condition: {type: 'Filter count at least'},
            method: {type: 'SCP'},
            method_data_redacted: true,
            filter: {
              id: 'filter-1',
              name: 'High results',
            },
            created_at: '2026-06-20T12:00:00Z',
            modified_at: '2026-06-20T12:30:00Z',
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({jwt: 'jwt-token'});

    const response = await fetchNativeAlerts(gmp, {
      page: 2,
      pageSize: 10,
      sort: '-event',
      filter: 'secops',
    });

    const alert = response.alerts[0];
    expect(response.counts.first).toEqual(11);
    expect(response.counts.filtered).toEqual(11);
    expect(alert.id).toEqual('4e110580-5281-4e8e-bbc5-322f3ef8d9e8');
    expect(alert.name).toEqual('Notify SecOps');
    expect(alert.comment).toEqual('Native metadata only');
    expect(alert.owner?.name).toEqual('admin');
    expect(alert.isActive()).toEqual(true);
    expect(alert.isInUse()).toEqual(true);
    expect(alert.event?.type).toEqual('Task run status changed');
    expect(alert.event?.data).toEqual({});
    expect(alert.condition?.type).toEqual('Filter count at least');
    expect(alert.condition?.data).toEqual({});
    expect(alert.method?.type).toEqual('SCP');
    expect(alert.method?.data).toEqual({});
    expect(alert.filter?.id).toEqual('filter-1');
    expect(alert.filter?.name).toEqual('High results');
    expect(alert.userCapabilities.mayEdit('alert')).toEqual(true);
    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/alerts', {
      token: 'test-token',
      page: 2,
      page_size: 10,
      sort: '-event',
      filter: 'secops',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/alerts',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
  });

  test('maps GSA filter state to the native alert collection query', () => {
    const filter = Filter.fromString(
      'first=26 rows=25 sort-reverse=event search=secops',
    );

    expect(nativeAlertsQueryFromFilter(filter)).toEqual({
      page: 2,
      pageSize: 25,
      sort: '-event',
      filter: 'secops',
    });
  });

  test('loads the alert store through same-origin native API', async () => {
    const filter = Filter.fromString(
      'first=1 rows=10 sort=condition search=secops',
    );
    const rootState = createState('alert', {
      isLoading: {
        [filterIdentifier(filter)]: false,
      },
    });
    const getState = testing.fn().mockReturnValue(rootState);
    const dispatch = testing.fn();
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {
          page: 1,
          page_size: 10,
          total: 1,
          sort: 'condition',
          filter: 'secops',
        },
        items: [
          {
            id: '4e110580-5281-4e8e-bbc5-322f3ef8d9e8',
            name: 'Notify SecOps',
            active: true,
            in_use: false,
            task_count: 0,
            event: {type: 'Task run status changed'},
            condition: {type: 'Filter count at least'},
            method: {type: 'SCP'},
            method_data_redacted: true,
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp();

    await loadEntities(gmp)(filter)(dispatch, getState);

    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/alerts', {
      token: 'test-token',
      page: 1,
      page_size: 10,
      sort: 'condition',
      filter: 'secops',
    });
    expect(dispatch).toHaveBeenCalledTimes(2);
    const successAction = dispatch.mock.calls[1][0];
    expect(successAction.type).toEqual('ENTITIES_LOADING_SUCCESS');
    expect(successAction.counts.filtered).toEqual(1);
    expect(successAction.data[0].name).toEqual('Notify SecOps');
    expect(successAction.data[0].condition.type).toEqual(
      'Filter count at least',
    );
  });
});
