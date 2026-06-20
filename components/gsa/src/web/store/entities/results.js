/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * Modified by TurboVAS contributors, 2026.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {createAll} from 'web/store/entities/utils/main';
import {
  fetchNativeResult,
  fetchNativeResults,
  nativeReportResultsQueryFromFilter,
} from 'gmp/native-api/reports';

const {
  loadAllEntities,
  loadEntities,
  loadEntity,
  reducer,
  selector,
  entitiesLoadingActions,
  entityLoadingActions,
} = createAll('result');

const canUseNativeApi = gmp => typeof gmp?.buildUrl === 'function';

const mergeNativeInformation = (inheritedInformation, nativeInformation) => {
  if (nativeInformation === undefined) {
    return inheritedInformation;
  }

  if (inheritedInformation === undefined) {
    return nativeInformation;
  }

  return Object.assign(
    Object.create(Object.getPrototypeOf(inheritedInformation)),
    inheritedInformation,
    {
      id: nativeInformation.id || inheritedInformation.id,
      name: nativeInformation.name || inheritedInformation.name,
      family: nativeInformation.family || inheritedInformation.family,
      solution: inheritedInformation.solution || nativeInformation.solution,
    },
  );
};

const mergeNativeMetadata = (inherited, native) =>
  Object.assign(Object.create(Object.getPrototypeOf(inherited)), inherited, {
    creationTime: native.creationTime || inherited.creationTime,
    host: native.host || inherited.host,
    port: native.port || inherited.port,
    qod: native.qod || inherited.qod,
    report: native.report || inherited.report,
    scan_nvt_version: native.scan_nvt_version || inherited.scan_nvt_version,
    severity: native.severity ?? inherited.severity,
    task: native.task || inherited.task,
    information: mergeNativeInformation(inherited.information, native.information),
  });

const nativeLoadEntities = gmp => filter => (dispatch, getState) => {
  if (!canUseNativeApi(gmp)) {
    return loadEntities(gmp)(filter)(dispatch, getState);
  }

  const rootState = getState();
  const state = selector(rootState);

  if (state.isLoadingEntities(filter)) {
    return Promise.resolve();
  }

  dispatch(entitiesLoadingActions.request(filter));

  return fetchNativeResults(gmp, nativeReportResultsQueryFromFilter(filter)).then(
    response =>
      dispatch(
        entitiesLoadingActions.success(
          response.results,
          filter,
          filter,
          response.counts,
        ),
      ),
    error => dispatch(entitiesLoadingActions.error(error, filter)),
  );
};

const nativeLoadEntity = gmp => id => (dispatch, getState) => {
  if (!canUseNativeApi(gmp)) {
    return loadEntity(gmp)(id)(dispatch, getState);
  }

  const rootState = getState();
  const state = selector(rootState);

  if (state.isLoadingEntity(id)) {
    return Promise.resolve();
  }

  dispatch(entityLoadingActions.request(id));

  return gmp.result
    .get({id})
    .then(inheritedResponse =>
      fetchNativeResult(gmp, id).then(
        nativeResponse =>
          dispatch(
            entityLoadingActions.success(
              id,
              mergeNativeMetadata(inheritedResponse.data, nativeResponse.result),
            ),
          ),
        () => dispatch(entityLoadingActions.success(id, inheritedResponse.data)),
      ),
    )
    .catch(error => dispatch(entityLoadingActions.error(id, error)));
};

export {
  loadAllEntities,
  nativeLoadEntities as loadEntities,
  nativeLoadEntity as loadEntity,
  reducer,
  selector,
  entitiesLoadingActions,
  entityLoadingActions,
};
