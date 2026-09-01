# Microsoft 365 Defender

Publisher: Splunk <br>
Connector Version: 2.0.3 <br>
Product Vendor: Microsoft <br>
Product Name: Microsoft 365 Defender <br>
Minimum Product Version: 7.0.0

This app integrates with Microsoft 365 Defender to execute various generic and investigative actions

## Port Information

The app uses HTTP/ HTTPS protocol for communicating with the Microsoft 365 Defender server. Below
are the default ports used by Splunk SOAR.

| SERVICE NAME | TRANSPORT PROTOCOL | PORT |
|--------------|--------------------|------|
| http | tcp | 80 |
| https | tcp | 443 |

## Explanation of Asset Configuration Parameters

- **Tenant ID**: The **Directory (tenant) ID** of your Microsoft Entra ID instance from the Azure portal.
- **Client ID**: The **Application (client) ID** of your registered application in Microsoft Entra ID.
- **Client Secret**: The secret string used by the application to prove its identity when requesting a token. This is required for **Client Secret Authentication**.
- **Non-Interactive Auth**: Check this box to use non-interactive (app-only) authentication. Uncheck it for interactive (user-based) authentication. You must re-run **Test Connectivity** after changing this setting.
- **Timeout**: The timeout in seconds for API requests.

## Explanation of Asset Configuration Parameters for On Poll

- **Max Incidents For Polling**: The maximum number of incidents to fetch in each polling cycle (Default: 1000).
- **Start Time**: The start time for polling incidents (e.g., `2023-01-01T00:00:00Z`). If not provided, the connector will poll for incidents from the last week. This filter is based on the `lastUpdateDateTime` of the incident.
- **Filter**: Additional OData filters for polling incidents (e.g., `status ne 'Active'`).

## Explanation of On Poll Behavior

- The default incident order is set to "lastUpdateDateTime," prioritizing the latest incidents as newest.
- The start time parameter value aligns with the lastUpdateDateTime of the incident.
- The maximum incidents parameter functions exclusively with scheduled and interval polling.
- For Example,if the maximum incident parameter is set to 100, the 'on_poll' feature must incorporate up to 100 distinct incidents, based on the provided filter and start time parameter value.

## Configure and set up permissions of the app created on the Microsoft Azure portal

1. Navigate to \<https://portal.azure.com and log in with a user that has permissions to create an app in Microsoft Entra ID.

1. Select **Microsoft Entra ID**.

1. Select **App registrations** from the left-side panel, then click **New Registration**.

1. In the registration form, choose a name for your application and click **Register**.

1. Select **API Permissions** from the left-side panel.

1. Click on **Add a permission**.

1. Under the **APIs my organization uses** section, search for and select **Microsoft Graph**.

1. Select and add the appropriate permissions from the list below, choosing between **Application** or **Delegated** permissions as per your [Authentication Type](#asset-configuration):

   - **Application Permissions**

     - `SecurityAlert.Read.All`
     - `SecurityAlert.ReadWrite.All`
     - `SecurityIncident.Read.All`
     - `SecurityIncident.ReadWrite.All`
     - `ThreatHunting.Read.All`

   - **Delegated Permissions**

     - `SecurityAlert.Read.All`
     - `SecurityAlert.ReadWrite.All`
     - `SecurityIncident.Read.All`
     - `SecurityIncident.ReadWrite.All`
     - `ThreatHunting.Read.All`

1. Click **Add a permission** again.

1. Under the **Microsoft APIs** section, click on **Microsoft Graph**.

1. Add the following **Delegated** permission:

   - `offline_access`

1. Click **Grant admin consent** for the permissions.

### Permissions Required for Each Action

This table lists the API permissions required for each action. For most use cases, **Application** permissions are recommended.

| Action | Application Permissions | Delegated Permissions |
| ------------------- | ------------------------------ | ------------------------------ |
| `test connectivity` | `SecurityAlert.Read.All` | `SecurityAlert.Read.All` |
| `on poll` | `SecurityIncident.Read.All` | `SecurityIncident.Read.All` |
| `run query` | `ThreatHunting.Read.All` | `ThreatHunting.Read.All` |
| `list incidents` | `SecurityIncident.Read.All` | `SecurityIncident.Read.All` |
| `list alerts` | `SecurityAlert.Read.All` | `SecurityAlert.Read.All` |
| `get incident` | `SecurityIncident.Read.All` | `SecurityIncident.Read.All` |
| `update incident` | `SecurityIncident.ReadWrite.All` | `SecurityIncident.ReadWrite.All` |
| `get alert` | `SecurityAlert.Read.All` | `SecurityAlert.Read.All` |
| `update alert` | `SecurityAlert.ReadWrite.All` | `SecurityAlert.ReadWrite.All` |

### Authentication Method

You can choose one of the following authentication methods:

#### Client Secret Authentication

1. Select the **Certificates & secrets** menu from the left-side panel.
1. Click **New client secret**.
1. Provide a description, select an expiration time, and click **Add**.
1. Copy the generated secret **Value**. You will need it to configure the asset and will not be able to retrieve it later.

#### Certificate Based Authentication

1. Select the **Certificates & secrets** menu from the left-side panel.
1. Select the **Certificates** tab.
1. Click **Upload Certificate** and choose a `.crt` file that contains the public key of your certificate.
1. Copy the **Thumbprint** for the newly uploaded certificate. You will need this when configuring the asset.

### Copy Application and Tenant ID

1. Select the **Overview** menu from the left-side panel.
1. Copy the **Application (client) ID** and **Directory (tenant) ID**. You will need these to configure the asset.

## Configure the Microsoft 365 Defender SOAR app's asset

### Asset Configuration

1. **Tenant ID**: Enter the **Directory (tenant) ID** you copied from your Azure application.

1. **Client ID**: Enter the **Application (client) ID** you copied from your Azure application.

1. **Authentication Type**: Choose your authentication method:

   - **For Client Secret Authentication**:

     - Enter the **Client Secret** you created.
     - Leave the **Certificate Thumbprint** and **Certificate Private Key** fields blank.

   - **For Certificate-Based Authentication**:

     - Enter the **Certificate Thumbprint** you copied.
     - Paste the contents of your certificate's private key (`.pem` file) into the **Certificate Private Key** field.
     - Ensure the **Non-Interactive Auth** checkbox is checked.

1. **Authentication Flow**:

   - **Interactive (Delegated Permissions)**:

     - Uncheck the **Non-Interactive Auth** checkbox and save the asset first, so that Splunk SOAR assigns it an asset ID.
     - The redirect URI to register in Azure is a webhook URL of the form:
       `https://<soar_host>:<webhook_port>/webhook/microsoft365defender_<appid>/<asset_id>/oauth_callback`
       `<webhook_port>` defaults to `3500` unless your Splunk SOAR instance has configured a different port for the webhooks feature, and `<asset_id>` is the numeric ID assigned to the asset you just saved.
     - In your Azure application, go to **Authentication** **Add a platform** **Web**.
     - Paste the resulting URL into the **Redirect URIs** field, select the **ID tokens** checkbox, and click **Save**.

   - **Non-Interactive (Application Permissions)**:

     - Check the **Non-Interactive Auth** checkbox.

1. **Save** the asset.

## Test Connectivity

### Interactive Method

1. Ensure the **Non-Interactive Auth** checkbox is **unchecked** in the asset configuration.
1. Click the **TEST CONNECTIVITY** button. A pop-up window will appear with a URL.
1. Open the URL in a new browser tab and complete the Microsoft login process to grant the required permissions.
1. After successful authentication, you will see a message confirming that the code was received. You can close the browser tab.
1. The 'Test Connectivity' pop-up window should now display a 'Test Connectivity Passed' message.

### Non-Interactive Method

1. Ensure the **Non-Interactive Auth** checkbox is **checked** in the asset configuration.
1. Click the **TEST CONNECTIVITY** button. The test will run without any user interaction.

## Explanation of Test Connectivity Workflow for Interactive auth and Non-Interactive auth

- This app uses (version 1.0) OAUTH 2.0 authorization code workflow APIs for generating the
  [access_token] and [refresh_token] pairs if the authentication method is interactive else
  [access_token] if authentication method is non-interactive is used for all the API calls to
  the Microsoft 365 Defender instance.

- Interactive authentication mechanism is a user-context based workflow and the permissions of the
  user also matter along with the API permissions set to define the scope and permissions of the
  generated tokens.

- Non-Interactive authentication mechanism is a user-context based workflow and the permissions of
  the user also matter along with the API permissions set to define the scope and permissions of
  the generated token.

- The step-by-step process for the entire authentication mechanism is explained below.

  - The first step is to get an application created in a specific tenant on the Microsoft Entra ID. Generate the [client_secret] for the configured application. The
    detailed steps have been mentioned in the earlier section.

  - Configure the Microsoft 365 Defender app's asset with appropriate values for [tenant_id],
    [client_id], and [client_secret] configuration parameters.

  - Run the test connectivity action for Interactive method.

    - Internally, the connectivity creates a URL for hitting the /authorize endpoint for the
      generation of the authorization code and displays it on the connectivity pop-up window.
      The user is requested to hit this URL in a browser new tab and complete the
      authorization request successfully resulting in the generation of an authorization code.
    - The authorization code generated in the above step is used by the connectivity to make
      the next API call to generate the [access_token] and [refresh_token] pair. The
      generated authorization code, [access_token], and [refresh_token] are stored in the
      state file of the app on the Splunk SOAR server.
    - The authorization code can be used only once to generate the pair of [access_token]
      and [refresh_token]. If the [access_token] expires, then the [refresh_token] is
      used internally automatically by the application to re-generate the [access_token] by
      making the corresponding API call. This entire autonomous workflow will seamlessly work
      until the [refresh_token] does not get expired. Once the [refresh_token] expires,
      the user will have to run the test connectivity action once again to generate the
      authorization code followed by the generation of an entirely fresh pair of
      [access_token] and [refresh_token]. The default expiration time for the
      [access_token] is 1 hour and that of the [refresh_token] is 90 days.
    - The successful run of the Test Connectivity ensures that a valid pair of
      [access_token] and [refresh_token] has been generated and stored in the app's state
      file. These tokens will be used in all the actions' execution flow to authorize their
      API calls to the Microsoft 365 Defender instance.

  - Run the test connectivity action for Non-Interactive method.

    - Internally, the application authenticates to Azure AD token issuance endpoint and
      requests an [access_token] then it will generate the [access_token].
    - The [access_token] generated in the above step is used by the test connectivity to
      make the next API call to verify the [access_token]. The generated [access_token] is
      stored in the state file of the app on the Splunk SOAR server.
    - If the [access_token] expires, then application will automatically re-generate the
      [access_token] by making the corresponding API call.
    - The successful run of the Test Connectivity ensures that a valid [access_token] has
      been generated and stored in the app's state file. This token will be used in all the
      actions execution flow to authorize their API calls to the Microsoft 365 Defender
      instance.

## State file permissions

Please check the permissions for the state file as mentioned below.

#### State file path

- state file path on instance: /opt/phantom/local_data/app_states/\<appid/\<asset_id_state.json

#### State file permissions

- File rights: rw-rw-r-- (664) (The Splunk SOAR user should have read and write access for the
  state file)
- File owner: Appropriate Splunk SOAR user

## Notes

- \<appid - The app ID is a fixed value for this app (`69a23453-0649-4f5b-8abd-c2b64b53ab5b`). It
  is also embedded in the webhook redirect URI used for interactive authentication, e.g.
  `https://<splunk_soar_host>:<webhook_port>/webhook/microsoft365defender_<appid>/<asset_id>/oauth_callback`
- \<asset_id - The asset ID will be available on the created asset's Splunk SOAR web URL e.g.
  https://\<splunk_soar_host/apps/\<app_number/asset/\<asset_id/

#### The app is configured and ready to be used now.

### Configuration variables

This table lists the configuration variables required to operate Microsoft 365 Defender. These variables are specified when configuring a Microsoft 365 Defender asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**tenant_id** | required | string | Tenant ID |
**client_id** | required | string | Client ID |
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
[make request](#action-make-request) - make request <br>
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

## action: 'make request'

make request

Type: **generic** <br>
Read only: **False**

'make request' action for the app. Used to handle arbitrary HTTP requests with the app's asset

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**http_method** | required | The HTTP method to use for the request. | string | |
**endpoint** | required | Microsoft Graph API endpoint to call, appended to the base URL (https://graph.microsoft.com/v1.0). Example: '/security/alerts_v2' | string | |
**headers** | optional | The headers to send with the request (JSON object). An example is {'Content-Type': 'application/json'} | string | |
**query_parameters** | optional | Parameters to append to the URL (JSON object or query string). An example is ?key=value&key2=value2 | string | |
**body** | optional | The body to send with the request (JSON object). An example is {'key': 'value', 'key2': 'value2'} | string | |
**timeout** | optional | The timeout for the request in seconds. | numeric | |
**verify_ssl** | optional | Whether to verify the SSL certificate. | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.http_method | string | | |
action_result.parameter.endpoint | string | | |
action_result.parameter.headers | string | | |
action_result.parameter.query_parameters | string | | |
action_result.parameter.body | string | | |
action_result.parameter.timeout | numeric | | |
action_result.parameter.verify_ssl | boolean | | |
action_result.data.\*.status_code | numeric | | 200 |
action_result.data.\*.response_body | string | | {"value": []} |
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
