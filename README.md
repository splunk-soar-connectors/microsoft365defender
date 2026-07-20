# Microsoft 365 Defender

Publisher: Splunk <br>
Connector Version: 1.5.1 <br>
Product Vendor: Microsoft <br>
Product Name: Microsoft 365 Defender <br>
Minimum Product Version: 6.2.1

This app integrates with Microsoft 365 Defender to execute various generic and investigative actions

### Configuration variables

This table lists the configuration variables required to operate Microsoft 365 Defender. These variables are specified when configuring a Microsoft 365 Defender asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**tenant_id** | required | string | Tenant ID |
**client_id** | required | password | Client ID |
**client_secret** | optional | password | Client Secret |
**certificate_thumbprint** | optional | password | Certificate Thumbprint (required for CBA) |
**certificate_private_key** | optional | password | Certificate Private Key (.PEM) |
**timeout** | optional | numeric | HTTP API timeout in seconds |
**non_interactive** | optional | boolean | Non-Interactive Auth |
**max_incidents_per_poll** | optional | numeric | Maximum Incidents for scheduled/interval polling for each cycle |
**start_time** | optional | string | Start time for schedule/interval/manual poll (Use this format: 1970-01-01T00:00:00Z) |
**filter** | optional | string | Filter incidents based on property (example: status ne 'active') |

### Supported Actions

[test connectivity](#action-test-connectivity) - test connectivity <br>
[on poll](#action-on-poll) - on poll <br>
[list alerts](#action-list-alerts) - Get the list of recent alerts <br>
[get alert](#action-get-alert) - Retrieve the properties and relationships of an alert object <br>
[list incidents](#action-list-incidents) - Get the list of recent incidents <br>
[get incident](#action-get-incident) - Retrieve the properties and relationships of an incident object <br>
[run query](#action-run-query) - An advanced search query <br>
[update alert](#action-update-alert) - Update the properties of an alert object <br>
[update incident](#action-update-incident) - Update the properties of an incident object

## action: 'test connectivity'

test connectivity

Type: **test** <br>
Read only: **True**

Basic test for app.

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'on poll'

on poll

Type: **ingest** <br>
Read only: **True**

Callback action for the on_poll ingest functionality

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**start_time** | optional | Start of time range, in epoch time (milliseconds). | numeric | |
**end_time** | optional | End of time range, in epoch time (milliseconds). | numeric | |
**container_count** | optional | Maximum number of container records to query for. | numeric | |
**artifact_count** | optional | Maximum number of artifact records to query for. | numeric | |
**container_id** | optional | Comma-separated list of container IDs to limit the ingestion to. | string | |

#### Action Output

No Output

## action: 'list alerts'

Get the list of recent alerts

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**limit** | optional | Maximum number of alerts to return | numeric | |
**offset** | optional | Number of alerts to skip | numeric | |
**filter** | optional | Filter alerts based on property | string | |
**orderby** | optional | Sort the alerts based on property | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.limit | numeric | | |
action_result.parameter.offset | numeric | | |
action_result.parameter.filter | string | | |
action_result.parameter.orderby | string | | |
action_result.data.\*.alertWebUrl | string | `url` | |
action_result.data.\*.assignedTo | string | `email` | |
action_result.data.\*.category | string | | |
action_result.data.\*.classification | string | | |
action_result.data.\*.createdDateTime | string | | |
action_result.data.\*.description | string | | |
action_result.data.\*.detectionSource | string | | |
action_result.data.\*.determination | string | | |
action_result.data.\*.id | string | `defender alert id` | |
action_result.data.\*.incidentId | string | `defender incident id` | |
action_result.data.\*.incidentWebUrl | string | `url` | |
action_result.data.\*.lastUpdateDateTime | string | | |
action_result.data.\*.providerAlertId | string | `defender alert id` | |
action_result.data.\*.serviceSource | string | | |
action_result.data.\*.severity | string | `defender severity` | |
action_result.data.\*.status | string | | |
action_result.data.\*.tenantId | string | | |
action_result.data.\*.title | string | | |
action_result.summary.total_alerts | numeric | | 10 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get alert'

Retrieve the properties and relationships of an alert object

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**alert_id** | required | ID of the alert | string | `defender alert id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.alert_id | string | `defender alert id` | |
action_result.data.\*.assignedTo | string | `email` | |
action_result.data.\*.category | string | | |
action_result.data.\*.classification | string | | |
action_result.data.\*.createdDateTime | string | | |
action_result.data.\*.description | string | | |
action_result.data.\*.detectionSource | string | | |
action_result.data.\*.determination | string | | |
action_result.data.\*.id | string | `defender alert id` | |
action_result.data.\*.incidentId | string | `defender incident id` | |
action_result.data.\*.incidentWebUrl | string | `url` | |
action_result.data.\*.lastUpdateDateTime | string | | |
action_result.data.\*.providerAlertId | string | `defender alert id` | |
action_result.data.\*.serviceSource | string | | |
action_result.data.\*.severity | string | `defender severity` | |
action_result.data.\*.status | string | | |
action_result.data.\*.tenantId | string | | |
action_result.data.\*.title | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list incidents'

Get the list of recent incidents

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**limit** | optional | Maximum number of incidents to return | numeric | |
**offset** | optional | Number of incidents to skip | numeric | |
**filter** | optional | Filter incidents based on property | string | |
**orderby** | optional | Order results based on property | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.limit | numeric | | |
action_result.parameter.offset | numeric | | |
action_result.parameter.filter | string | | |
action_result.parameter.orderby | string | | |
action_result.data.\*.assignedTo | string | `email` | |
action_result.data.\*.classification | string | | |
action_result.data.\*.comments.\*.comment | string | | |
action_result.data.\*.comments.\*.createdByDisplayName | string | | |
action_result.data.\*.comments.\*.createdDateTime | string | | |
action_result.data.\*.createdDateTime | string | | |
action_result.data.\*.determination | string | | |
action_result.data.\*.displayName | string | | |
action_result.data.\*.id | string | `defender incident id` | |
action_result.data.\*.incidentWebUrl | string | `url` | |
action_result.data.\*.lastUpdateDateTime | string | | |
action_result.data.\*.redirectIncidentId | string | `defender incident id` | |
action_result.data.\*.severity | string | `defender severity` | |
action_result.data.\*.status | string | | |
action_result.data.\*.tenantId | string | | |
action_result.data.\*.summary | string | | |
action_result.data.\*.description | string | | |
action_result.data.\*.lastModifiedBy | string | | |
action_result.data.\*.resolvingComment | string | | |
action_result.summary.total_incidents | numeric | | 10 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get incident'

Retrieve the properties and relationships of an incident object

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**incident_id** | required | ID of the incident to retrieve | string | `defender incident id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.incident_id | string | `defender incident id` | |
action_result.data.\*.assignedTo | string | `email` | |
action_result.data.\*.classification | string | | |
action_result.data.\*.comments.\*.comment | string | | |
action_result.data.\*.comments.\*.createdByDisplayName | string | | |
action_result.data.\*.comments.\*.createdDateTime | string | | |
action_result.data.\*.createdDateTime | string | | |
action_result.data.\*.determination | string | | |
action_result.data.\*.displayName | string | | |
action_result.data.\*.id | string | `defender incident id` | |
action_result.data.\*.incidentWebUrl | string | `url` | |
action_result.data.\*.lastUpdateDateTime | string | | |
action_result.data.\*.redirectIncidentId | string | `defender incident id` | |
action_result.data.\*.severity | string | `defender severity` | |
action_result.data.\*.status | string | | |
action_result.data.\*.tags.\* | string | | |
action_result.data.\*.tenantId | string | `microsoft tenantid` | |
action_result.data.\*.summary | string | | |
action_result.data.\*.description | string | | |
action_result.data.\*.odata_context | string | | |
action_result.data.\*.lastModifiedBy | string | | |
action_result.data.\*.resolvingComment | string | | |
action_result.data.\*.@odata.context | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'run query'

An advanced search query

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**query** | required | Query to fetch results | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.query | string | | |
action_result.data.\*.DeviceId | string | | xxxxx9d48ec4859bd94a25039dcba09f4fd9ac78 |
action_result.data.\*.FileName | string | | test.exe |
action_result.data.\*.InitiatingProcessFileName | string | | powershell.exe |
action_result.data.\*.Timestamp | string | | 2022-06-12T04:24:25.0406516Z |
action_result.data.\*.odata_context | string | | https://test.com/v1.0/$metadata/incidents/$entity |
action_result.data.\*.additionalData.Intent_odata_type | string | | #Int64 |
action_result.data.\*.evidence.\*.odata_type | string | | #test.graph.security.deviceEvidence |
action_result.data.\*.Intent_odata_type | string | | #Int64 |
action_result.summary.total_results | numeric | | 1 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'update alert'

Update the properties of an alert object

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**alert_id** | required | ID of the alert | string | `defender alert id` |
**status** | optional | Specify the current status of the alert | string | |
**assign_to** | optional | Owner of the alert | string | `email` |
**classification** | optional | Specification of the alert | string | |
**determination** | optional | Specifies the determination of the alert | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.alert_id | string | `defender alert id` | |
action_result.parameter.status | string | | |
action_result.parameter.assign_to | string | `email` | |
action_result.parameter.classification | string | | |
action_result.parameter.determination | string | | |
action_result.data.\*.assignedTo | string | `email` | |
action_result.data.\*.category | string | | |
action_result.data.\*.classification | string | | |
action_result.data.\*.createdDateTime | string | | |
action_result.data.\*.description | string | | |
action_result.data.\*.detectionSource | string | | |
action_result.data.\*.determination | string | | |
action_result.data.\*.id | string | `defender alert id` | |
action_result.data.\*.incidentId | string | `defender incident id` | |
action_result.data.\*.incidentWebUrl | string | `url` | |
action_result.data.\*.lastUpdateDateTime | string | | |
action_result.data.\*.providerAlertId | string | `defender alert id` | |
action_result.data.\*.serviceSource | string | | |
action_result.data.\*.severity | string | `defender severity` | |
action_result.data.\*.status | string | | |
action_result.data.\*.tenantId | string | | |
action_result.data.\*.title | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'update incident'

Update the properties of an incident object

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**incident_id** | required | ID of the incident to update | string | `defender incident id` |
**status** | optional | Specify the current status of the incident | string | |
**assign_to** | optional | Owner of the incident | string | |
**classification** | optional | Specification of the incident | string | |
**determination** | optional | Specifies the determination of the incident | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.incident_id | string | `defender incident id` | |
action_result.parameter.status | string | | |
action_result.parameter.assign_to | string | | |
action_result.parameter.classification | string | | |
action_result.parameter.determination | string | | |
action_result.data.\*.assignedTo | string | `email` | |
action_result.data.\*.classification | string | | |
action_result.data.\*.createdDateTime | string | | |
action_result.data.\*.determination | string | | |
action_result.data.\*.displayName | string | | |
action_result.data.\*.id | string | `defender incident id` | |
action_result.data.\*.incidentWebUrl | string | `url` | |
action_result.data.\*.lastUpdateDateTime | string | | |
action_result.data.\*.redirectIncidentId | string | `defender incident id` | |
action_result.data.\*.severity | string | `defender severity` | |
action_result.data.\*.status | string | | |
action_result.data.\*.tenantId | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2026 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
