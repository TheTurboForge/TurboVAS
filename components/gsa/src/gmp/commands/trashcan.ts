/* SPDX-FileCopyrightText: 2024 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import HttpCommand from 'gmp/commands/http';
import type Response from 'gmp/http/response';
import {type XmlMeta, type XmlResponseData} from 'gmp/http/transform/fast-xml';
import AgentGroup from 'gmp/models/agent-group';
import Alert from 'gmp/models/alert';
import Credential from 'gmp/models/credential';
import Filter from 'gmp/models/filter';
import Group from 'gmp/models/group';
import {type ModelElement} from 'gmp/models/model';
import Override from 'gmp/models/override';
import Permission from 'gmp/models/permission';
import PortList from 'gmp/models/port-list';
import ReportConfig from 'gmp/models/report-config';
import ReportFormat from 'gmp/models/report-format';
import Role from 'gmp/models/role';
import ScanConfig from 'gmp/models/scan-config';
import Scanner from 'gmp/models/scanner';
import Schedule from 'gmp/models/schedule';
import Tag from 'gmp/models/tag';
import Target from 'gmp/models/target';
import Task from 'gmp/models/task';
import {map} from 'gmp/utils/array';
import {apiType, type EntityType} from 'gmp/utils/entity-type';

export interface TrashCanGetData {
  alerts: Alert[];
  scanConfigs: ScanConfig[];
  credentials: Credential[];
  filters: Filter[];
  groups: Group[];
  overrides: Override[];
  permissions: Permission[];
  portLists: PortList[];
  reportConfigs: ReportConfig[];
  reportFormats: ReportFormat[];
  roles: Role[];
  scanners: Scanner[];
  schedules: Schedule[];
  tags: Tag[];
  targets: Target[];
  tasks: Task[];
  agentGroups: AgentGroup[];
  failedRequests?: string[];
}

interface UsageTypeElement extends ModelElement {
  usage_type?: string;
}

interface AlertResponseData {
  get_alerts_response?: {
    alert: ModelElement[] | ModelElement;
  };
}

interface ConfigsResponseData {
  get_configs_response?: {
    config: UsageTypeElement[] | UsageTypeElement;
  };
}

interface CredentialsResponseData {
  get_credentials_response?: {
    credential: ModelElement[] | ModelElement;
  };
}

interface FiltersResponseData {
  get_filters_response?: {
    filter: ModelElement[] | ModelElement;
  };
}

interface GroupsResponseData {
  get_groups_response?: {
    group: ModelElement[] | ModelElement;
  };
}

interface OverridesResponseData {
  get_overrides_response?: {
    override: ModelElement[] | ModelElement;
  };
}

interface PermissionsResponseData {
  get_permissions_response?: {
    permission: ModelElement[] | ModelElement;
  };
}

interface PortListsResponseData {
  get_port_lists_response?: {
    port_list: ModelElement[] | ModelElement;
  };
}

interface ReportConfigsResponseData {
  get_report_configs_response?: {
    report_config: ModelElement[] | ModelElement;
  };
}

interface ReportFormatsResponseData {
  get_report_formats_response?: {
    report_format: ModelElement[] | ModelElement;
  };
}

interface RolesResponseData {
  get_roles_response?: {
    role: ModelElement[] | ModelElement;
  };
}

interface ScannersResponseData {
  get_scanners_response?: {
    scanner: ModelElement[] | ModelElement;
  };
}

interface SchedulesResponseData {
  get_schedules_response?: {
    schedule: ModelElement[] | ModelElement;
  };
}

interface TagsResponseData {
  get_tags_response?: {
    tag: ModelElement[] | ModelElement;
  };
}

interface TargetsResponseData {
  get_targets_response?: {
    target: ModelElement[] | ModelElement;
  };
}

interface TasksResponseData {
  get_tasks_response?: {
    task: UsageTypeElement[] | UsageTypeElement;
  };
}

interface AgentGroupResponseData {
  get_agent_groups_response?: {
    agent_group: ModelElement[] | ModelElement;
  };
}

interface TrashCanGetResponseData<TData> extends XmlResponseData {
  get_trash: TData;
}

type TrashCanGetResponse<TData> = Response<
  TrashCanGetResponseData<TData>,
  XmlMeta
>;

type TrashCanGetPromise<TData> = Promise<TrashCanGetResponse<TData>>;

class TrashCanCommand extends HttpCommand {
  async restore({id}: {id: string}) {
    const data = {
      cmd: 'restore',
      target_id: id,
    };
    await this.httpPostWithTransform(data);
  }

  async delete({id, entityType}: {id: string; entityType: EntityType}) {
    const cmdApiType = apiType(entityType);
    const cmd = 'delete_from_trash';
    const typeId = cmdApiType + '_id';
    await this.httpPostWithTransform({
      cmd,
      [typeId]: id,
      resource_type: cmdApiType,
    });
  }

  async empty() {
    await this.httpPostWithTransform({cmd: 'empty_trashcan'});
  }

  async get({
    agentGroups: requestAgentGroups = false,
  }: {
    agentGroups?: boolean;
  } = {}): Promise<Response<TrashCanGetData, XmlMeta>> {
    const alertsRequest = this.httpGetWithTransform({
      cmd: 'get_trash_alerts',
    }) as TrashCanGetPromise<AlertResponseData>;
    const configsRequest = this.httpGetWithTransform({
      cmd: 'get_trash_configs',
    }) as TrashCanGetPromise<ConfigsResponseData>;
    const credentialsRequest = this.httpGetWithTransform({
      cmd: 'get_trash_credentials',
    }) as TrashCanGetPromise<CredentialsResponseData>;
    const filtersRequest = this.httpGetWithTransform({
      cmd: 'get_trash_filters',
    }) as TrashCanGetPromise<FiltersResponseData>;
    const groupsRequest = this.httpGetWithTransform({
      cmd: 'get_trash_groups',
    }) as TrashCanGetPromise<GroupsResponseData>;
    const overridesRequest = this.httpGetWithTransform({
      cmd: 'get_trash_overrides',
    }) as TrashCanGetPromise<OverridesResponseData>;
    const permissionsRequest = this.httpGetWithTransform({
      cmd: 'get_trash_permissions',
    }) as TrashCanGetPromise<PermissionsResponseData>;
    const portListsRequest = this.httpGetWithTransform({
      cmd: 'get_trash_port_lists',
    }) as TrashCanGetPromise<PortListsResponseData>;
    const reportConfigsRequest = this.httpGetWithTransform({
      cmd: 'get_trash_report_configs',
    }) as TrashCanGetPromise<ReportConfigsResponseData>;
    const reportFormatsRequest = this.httpGetWithTransform({
      cmd: 'get_trash_report_formats',
    }) as TrashCanGetPromise<ReportFormatsResponseData>;
    const rolesRequest = this.httpGetWithTransform({
      cmd: 'get_trash_roles',
    }) as TrashCanGetPromise<RolesResponseData>;
    const scannersRequest = this.httpGetWithTransform({
      cmd: 'get_trash_scanners',
    }) as TrashCanGetPromise<ScannersResponseData>;
    const schedulesRequest = this.httpGetWithTransform({
      cmd: 'get_trash_schedules',
    }) as TrashCanGetPromise<SchedulesResponseData>;
    const tagsRequest = this.httpGetWithTransform({
      cmd: 'get_trash_tags',
    }) as TrashCanGetPromise<TagsResponseData>;
    const targetsRequest = this.httpGetWithTransform({
      cmd: 'get_trash_targets',
    }) as TrashCanGetPromise<TargetsResponseData>;
    const tasksRequest = this.httpGetWithTransform({
      cmd: 'get_trash_tasks',
    }) as TrashCanGetPromise<TasksResponseData>;
    const agentGroupRequest = requestAgentGroups
      ? (this.httpGetWithTransform({
          cmd: 'get_trash_agent_group',
        }) as TrashCanGetPromise<AgentGroupResponseData>)
      : Promise.resolve();
    const requests = [
      alertsRequest,
      configsRequest,
      credentialsRequest,
      filtersRequest,
      groupsRequest,
      overridesRequest,
      permissionsRequest,
      portListsRequest,
      reportConfigsRequest,
      reportFormatsRequest,
      rolesRequest,
      scannersRequest,
      schedulesRequest,
      tagsRequest,
      targetsRequest,
      tasksRequest,
      agentGroupRequest,
    ];

    const results = await Promise.allSettled(requests);

    const getResponse = <T>(index: number): T | null =>
      results[index].status === 'fulfilled'
        ? (results[index].value as T)
        : null;

    const failedRequests: string[] = [];
    const requestNames = [
      'alerts',
      'configs',
      'credentials',
      'filters',
      'groups',
      'overrides',
      'permissions',
      'portLists',
      'reportConfigs',
      'reportFormats',
      'roles',
      'scanners',
      'schedules',
      'tags',
      'targets',
      'tasks',
      'agentGroups',
    ];

    results.forEach((result, index) => {
      if (result.status === 'rejected') {
        failedRequests.push(requestNames[index]);
      }
    });

    const [
      alertsResponse,
      configsResponse,
      credentialsResponse,
      filtersResponse,
      groupsResponse,
      overridesResponse,
      permissionsResponse,
      portListsResponse,
      reportConfigsResponse,
      reportFormatsResponse,
      rolesResponse,
      scannersResponse,
      schedulesResponse,
      tagsResponse,
      targetsResponse,
      tasksResponse,
      agentGroupsResponse,
    ] = [
      getResponse<TrashCanGetResponse<AlertResponseData>>(0),
      getResponse<TrashCanGetResponse<ConfigsResponseData>>(1),
      getResponse<TrashCanGetResponse<CredentialsResponseData>>(2),
      getResponse<TrashCanGetResponse<FiltersResponseData>>(3),
      getResponse<TrashCanGetResponse<GroupsResponseData>>(4),
      getResponse<TrashCanGetResponse<OverridesResponseData>>(5),
      getResponse<TrashCanGetResponse<PermissionsResponseData>>(6),
      getResponse<TrashCanGetResponse<PortListsResponseData>>(7),
      getResponse<TrashCanGetResponse<ReportConfigsResponseData>>(8),
      getResponse<TrashCanGetResponse<ReportFormatsResponseData>>(9),
      getResponse<TrashCanGetResponse<RolesResponseData>>(10),
      getResponse<TrashCanGetResponse<ScannersResponseData>>(11),
      getResponse<TrashCanGetResponse<SchedulesResponseData>>(12),
      getResponse<TrashCanGetResponse<TagsResponseData>>(13),
      getResponse<TrashCanGetResponse<TargetsResponseData>>(14),
      getResponse<TrashCanGetResponse<TasksResponseData>>(15),
      getResponse<TrashCanGetResponse<AgentGroupResponseData>>(16),
    ];
    const alertsData = alertsResponse?.data.get_trash;
    const configsData = configsResponse?.data.get_trash;
    const credentialsData = credentialsResponse?.data.get_trash;
    const filtersData = filtersResponse?.data.get_trash;
    const groupsData = groupsResponse?.data.get_trash;
    const overridesData = overridesResponse?.data.get_trash;
    const permissionsData = permissionsResponse?.data.get_trash;
    const portListsData = portListsResponse?.data.get_trash;
    const reportConfigsData = reportConfigsResponse?.data.get_trash;
    const reportFormatsData = reportFormatsResponse?.data.get_trash;
    const rolesData = rolesResponse?.data.get_trash;
    const scannersData = scannersResponse?.data.get_trash;
    const schedulesData = schedulesResponse?.data.get_trash;
    const tagsData = tagsResponse?.data.get_trash;
    const targetsData = targetsResponse?.data.get_trash;
    const tasksData = tasksResponse?.data.get_trash;
    const agentGroupsData = agentGroupsResponse?.data.get_trash;

    const alerts = map(alertsData?.get_alerts_response?.alert, element =>
      Alert.fromElement(element),
    );

    const scanConfigs = map(configsData?.get_configs_response?.config, element =>
      ScanConfig.fromElement(element),
    );

    const credentials = map(
      credentialsData?.get_credentials_response?.credential,
      element => Credential.fromElement(element),
    );
    const filters = map(filtersData?.get_filters_response?.filter, element =>
      Filter.fromElement(element),
    );
    const groups = map(groupsData?.get_groups_response?.group, element =>
      Group.fromElement(element),
    );
    const overrides = map(
      overridesData?.get_overrides_response?.override,
      element => Override.fromElement(element),
    );
    const permissions = map(
      permissionsData?.get_permissions_response?.permission,
      element => Permission.fromElement(element),
    );
    const portLists = map(
      portListsData?.get_port_lists_response?.port_list,
      element => PortList.fromElement(element),
    );
    const reportConfigs = map(
      reportConfigsData?.get_report_configs_response?.report_config,
      element => ReportConfig.fromElement(element),
    );
    const reportFormats = map(
      reportFormatsData?.get_report_formats_response?.report_format,
      element => ReportFormat.fromElement(element),
    );
    const roles = map(rolesData?.get_roles_response?.role, element =>
      Role.fromElement(element),
    );
    const scanners = map(
      scannersData?.get_scanners_response?.scanner,
      element => Scanner.fromElement(element),
    );
    const schedules = map(
      schedulesData?.get_schedules_response?.schedule,
      element => Schedule.fromElement(element),
    );
    const tags = map(tagsData?.get_tags_response?.tag, element =>
      Tag.fromElement(element),
    );
    const targets = map(targetsData?.get_targets_response?.target, element =>
      Target.fromElement(element),
    );
    const tasks = map(tasksData?.get_tasks_response?.task, element =>
      Task.fromElement(element),
    );
    const agentGroups = map(
      agentGroupsData?.get_agent_groups_response?.agent_group,
      element => AgentGroup.fromElement(element),
    );
    const baseResponse =
      targetsResponse ||
      alertsResponse ||
      configsResponse ||
      credentialsResponse ||
      filtersResponse ||
      groupsResponse ||
      overridesResponse ||
      permissionsResponse ||
      portListsResponse ||
      reportConfigsResponse ||
      reportFormatsResponse ||
      rolesResponse ||
      scannersResponse ||
      schedulesResponse ||
      tagsResponse ||
      tasksResponse ||
      agentGroupsResponse;

    if (!baseResponse) {
      // If all requests failed, throw an error
      throw new Error('All trash can requests failed');
    }

    return baseResponse.setData({
      alerts,
      scanConfigs,
      credentials,
      filters,
      groups,
      overrides,
      permissions,
      portLists,
      reportConfigs,
      reportFormats,
      roles,
      scanners,
      schedules,
      tags,
      targets,
      tasks,
      agentGroups,
      failedRequests: failedRequests.length > 0 ? failedRequests : undefined,
    });
  }
}

export default TrashCanCommand;
