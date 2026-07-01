/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type Response from 'gmp/http/response';
import type {Meta} from 'gmp/http/response';
import type Model from 'gmp/models/model';
import {type EntityType} from 'gmp/utils/entity-type';
import useEntityClone, {
  type EntityCloneResponse,
} from 'web/entity/hooks/useEntityClone';
import useEntityCreate, {
  type EntityCreateResponse,
} from 'web/entity/hooks/useEntityCreate';
import useEntityDelete from 'web/entity/hooks/useEntityDelete';
import useEntityDownload, {
  type OnDownloadedFunc,
} from 'web/entity/hooks/useEntityDownload';
import useEntitySave, {
  type EntitySaveResponse,
} from 'web/entity/hooks/useEntitySave';
import useGmp from 'web/hooks/useGmp';
import type {GenerateFilenameParams} from 'web/utils/Render';

type EntityDownloadOverride<TEntity> = (
  entity: TEntity,
) => Promise<Response<string | ArrayBuffer, Meta>>;

interface EntityComponentRenderProps<
  TEntity,
  TCreateData,
  TCreateResponse,
  TSaveData,
  TSaveResponse,
> {
  delete: (entity: TEntity) => Promise<void>;
  create: (data: TCreateData) => Promise<TCreateResponse | void>;
  clone: (entity: TEntity) => Promise<void>;
  download: (entity: TEntity) => Promise<void>;
  save: (entity: TSaveData) => Promise<TSaveResponse | void>;
}

interface EntityComponentProps<
  TEntity,
  TCreateData,
  TCreateResponse,
  TSaveData,
  TSaveResponse,
  TCloneResponse,
> {
  name: EntityType;
  children: (
    props: EntityComponentRenderProps<
      TEntity,
      TCreateData,
      TCreateResponse,
      TSaveData,
      TSaveResponse
    >,
  ) => React.ReactNode;
  download?: EntityDownloadOverride<TEntity>;
  downloadOptions?: GenerateFilenameParams;
  onDownloaded?: OnDownloadedFunc;
  onDownloadError?: (error: Error) => void;
  onSaved?: (response: TSaveResponse) => void;
  onSaveError?: (error: Error) => void;
  onCreated?: (response: TCreateResponse) => void;
  onCreateError?: (error: Error) => void;
  onDeleted?: () => void;
  onDeleteError?: (error: Error) => void;
  onCloned?: (response: TCloneResponse) => void;
  onCloneError?: (error: Error) => void;
}

const EntityComponent = <
  TEntity extends Model,
  TCreateData = {},
  TCreateResponse = EntityCreateResponse,
  TSaveData = {},
  TSaveResponse = EntitySaveResponse,
  TCloneResponse = EntityCloneResponse,
>({
  children,
  download,
  downloadOptions,
  name,
  onDownloaded,
  onDownloadError,
  onSaved,
  onSaveError,
  onCreated,
  onCreateError,
  onDeleted,
  onDeleteError,
  onCloned,
  onCloneError,
}: EntityComponentProps<
  TEntity,
  TCreateData,
  TCreateResponse,
  TSaveData,
  TSaveResponse,
  TCloneResponse
>) => {
  const gmp = useGmp();
  const cmd = gmp[name];
  const handleEntityDownload = useEntityDownload<TEntity>(
    entity => (download ?? cmd.export)(entity),
    {
      onDownloadError,
      onDownloaded,
    },
  );

  const handleEntitySave = useEntitySave<TSaveData, TSaveResponse>(
    data => cmd.save(data),
    {
      onSaveError,
      onSaved,
    },
  );

  const handleEntityCreate = useEntityCreate<TCreateData, TCreateResponse>(
    data => cmd.create(data),
    {
      onCreated,
      onCreateError,
    },
  );

  const handleEntityDelete = useEntityDelete<TEntity>(
    entity => cmd.delete(entity),
    {
      onDeleteError,
      onDeleted,
    },
  );

  const handleEntityClone = useEntityClone<TEntity, TCloneResponse>(
    entity => cmd.clone(entity),
    {
      onCloneError,
      onCloned,
    },
  );

  return children({
    create: handleEntityCreate,
    clone: handleEntityClone,
    delete: handleEntityDelete,
    save: handleEntitySave,
    download: entity => handleEntityDownload(entity, downloadOptions),
  });
};

export default EntityComponent;
