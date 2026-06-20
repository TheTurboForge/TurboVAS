/* SPDX-FileCopyrightText: 2026 TurboVAS contributors
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, expect, test, testing} from '@gsa/testing';
import Result from 'gmp/models/result';
import {fetchNativeResult, fetchNativeResults} from 'gmp/native-api/reports';
import {loadEntity} from 'web/store/entities/results';

const createGmp = ({jwt, token = 'test-token'}: {jwt?: string; token?: string} = {}) => ({
  buildUrl: testing.fn((path: string) => `https://turbovas.example/${path}`),
  session: {jwt, token},
});

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('native API result list', () => {
  test('fetches top-level results as inherited Result models', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 25, total: 1, sort: '-severity', filter: ''},
        items: [
          {
            id: 'result-1',
            host: '192.168.178.42',
            host_asset_id: 'host-asset-1',
            hostname: 'workstation.local',
            port: '443/tcp',
            nvt_oid: '1.3.6.1.4.1.25623.1.0.900001',
            name: 'Example vulnerability',
            nvt_family: 'General',
            description_excerpt: 'Example detection text',
            solution_type: 'VendorFix',
            solution: 'Install the vendor fix.',
            severity: 7.5,
            qod: 80,
            scan_nvt_version: '20260618T1200',
            created_at: '2026-06-18T20:00:00Z',
            report: {id: 'report-1', name: 'Full and fast'},
            task: {id: 'task-1', name: 'LAN scan'},
            source_report_id: 'report-1',
            raw_evidence_href: '/result/result-1',
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({jwt: 'jwt-token'});

    const response = await fetchNativeResults(gmp, {
      page: 1,
      pageSize: 25,
      sort: '-severity',
      filter: '',
    });

    const result = response.results[0];
    expect(response.counts.filtered).toEqual(1);
    expect(result.id).toEqual('result-1');
    expect(result.name).toEqual('Example vulnerability');
    expect(result.severity).toEqual(7.5);
    expect(result.qod?.value).toEqual(80);
    expect(result.host?.name).toEqual('192.168.178.42');
    expect(result.host?.id).toEqual('host-asset-1');
    expect(result.host?.hostname).toEqual('workstation.local');
    expect(result.port).toEqual('443/tcp');
    expect(result.information?.id).toEqual('1.3.6.1.4.1.25623.1.0.900001');
    expect(result.information?.name).toEqual('Example vulnerability');
    expect((result.information as {solution?: {type?: string}})?.solution?.type).toEqual('VendorFix');
    expect(result.report?.id).toEqual('report-1');
    expect(result.task?.id).toEqual('task-1');
    expect(result.scan_nvt_version).toEqual('20260618T1200');
    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/results', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: '-severity',
      filter: '',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/results',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
  });

  test('fetches one result from the native detail endpoint', async () => {
    const id = '9d77c6b6-dcb2-4a38-87f7-3bb77cf60cf1';
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id,
        host: '192.168.178.42',
        host_asset_id: '77777777-7777-4777-8777-777777777777',
        hostname: 'workstation.local',
        port: '443/tcp',
        nvt_oid: '1.3.6.1.4.1.25623.1.0.900001',
        name: 'Example vulnerability',
        nvt_family: 'General',
        description_excerpt: 'Example detection text',
        solution_type: 'VendorFix',
        solution: 'Install the vendor fix.',
        severity: 7.5,
        qod: 80,
        scan_nvt_version: '20260618T1200',
        created_at: '2026-06-18T20:00:00Z',
        report: {id: 'report-1', name: 'Full and fast'},
        task: {id: 'task-1', name: 'LAN scan'},
        source_report_id: 'report-1',
        raw_evidence_href: `/result/${id}`,
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({jwt: 'jwt-token'});

    const response = await fetchNativeResult(gmp, id);

    expect(response.result).toBeInstanceOf(Result);
    expect(response.result.id).toEqual(id);
    expect(response.result.name).toEqual('Example vulnerability');
    expect(response.result.host?.id).toEqual(
      '77777777-7777-4777-8777-777777777777',
    );
    expect(response.result.report?.id).toEqual('report-1');
    expect(response.result.task?.name).toEqual('LAN scan');
    expect(gmp.buildUrl).toHaveBeenCalledWith(`api/v1/results/${id}`, {
      token: 'test-token',
    });
  });

  test('loads inherited detail before overlaying native metadata', async () => {
    const id = '9d77c6b6-dcb2-4a38-87f7-3bb77cf60cf1';
    const calls: string[] = [];
    const inherited = Result.fromElement({
      _id: id,
      name: 'Inherited result',
      host: {__text: '192.168.178.42'},
      port: '80/tcp',
      nvt: {
        _oid: '1.3.6.1.4.1.25623.1.0.900001',
        type: 'nvt',
        name: 'Inherited NVT',
        tags: 'summary=Inherited summary|vuldetect=Inherited detection',
      },
      description: 'Full inherited result description',
      severity: 5.0,
      qod: {value: 70},
      report: {_id: 'report-inherited'},
      task: {_id: 'task-inherited', name: 'Inherited task'},
      overrides: {
        override: [{_id: 'override-1', text: 'Retained override', active: 1}],
      },
    });
    const fetchMock = testing.fn().mockImplementation(() => {
      calls.push('native');
      return Promise.resolve({
        json: testing.fn().mockResolvedValue({
          id,
          host: '192.168.178.43',
          host_asset_id: '77777777-7777-4777-8777-777777777777',
          hostname: 'workstation.local',
          port: '443/tcp',
          nvt_oid: '1.3.6.1.4.1.25623.1.0.900001',
          name: 'Native result metadata',
          nvt_family: 'Native family',
          description_excerpt: 'Native excerpt only',
          solution_type: 'VendorFix',
          solution: 'Native solution',
          severity: 7.5,
          qod: 80,
          scan_nvt_version: '20260618T1200',
          created_at: '2026-06-18T20:00:00Z',
          report: {id: 'report-native', name: 'Native report'},
          task: {id: 'task-native', name: 'Native task'},
          source_report_id: 'report-native',
          raw_evidence_href: `/result/${id}`,
        }),
        ok: true,
        status: 200,
      });
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = {
      ...createGmp({jwt: 'jwt-token'}),
      result: {
        get: testing.fn().mockImplementation(() => {
          calls.push('gmp');
          return Promise.resolve({data: inherited});
        }),
      },
    };
    const actions: Array<{type: string; data?: Result}> = [];
    const dispatch = testing.fn(action => {
      actions.push(action);
      return action;
    });
    const getState = () => ({
      entities: {
        result: {
          byId: {},
          errors: {},
          isLoading: {},
        },
      },
    });

    await loadEntity(gmp)(id)(dispatch, getState);

    const success = actions.find(
      action => action.type === 'ENTITY_LOADING_SUCCESS',
    );
    const result = success?.data;
    expect(calls).toEqual(['gmp', 'native']);
    expect(gmp.result.get).toHaveBeenCalledWith({id});
    expect(result).toBeInstanceOf(Result);
    expect(result?.description).toEqual('Full inherited result description');
    expect(result?.overrides[0].text).toEqual('Retained override');
    expect(
      (result?.information as {tags?: {summary?: string}} | undefined)?.tags
        ?.summary,
    ).toEqual('Inherited summary');
    expect(result?.host?.name).toEqual('192.168.178.43');
    expect(result?.host?.id).toEqual('77777777-7777-4777-8777-777777777777');
    expect(result?.port).toEqual('443/tcp');
    expect(result?.severity).toEqual(7.5);
    expect(result?.qod?.value).toEqual(80);
    expect(result?.report?.id).toEqual('report-native');
    expect(result?.task?.name).toEqual('Native task');
    expect(result?.scan_nvt_version).toEqual('20260618T1200');
  });

  test('keeps inherited result detail when the native overlay fails', async () => {
    const id = '9d77c6b6-dcb2-4a38-87f7-3bb77cf60cf1';
    const inherited = Result.fromElement({
      _id: id,
      name: 'Inherited result',
      description: 'Full inherited result description',
      severity: 5.0,
      qod: {value: 70},
    });
    testing.stubGlobal('fetch', testing.fn().mockRejectedValue(new Error('404')));
    const gmp = {
      ...createGmp({jwt: 'jwt-token'}),
      result: {
        get: testing.fn().mockResolvedValue({data: inherited}),
      },
    };
    const actions: Array<{type: string; data?: Result}> = [];
    const dispatch = testing.fn(action => {
      actions.push(action);
      return action;
    });
    const getState = () => ({
      entities: {
        result: {
          byId: {},
          errors: {},
          isLoading: {},
        },
      },
    });

    await loadEntity(gmp)(id)(dispatch, getState);

    const success = actions.find(
      action => action.type === 'ENTITY_LOADING_SUCCESS',
    );
    expect(success?.data).toBe(inherited);
  });
});
