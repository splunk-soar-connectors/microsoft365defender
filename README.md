# Microsoft 365 Defender

Publisher: Splunk \
Connector Version: 1.4.3 \
Product Vendor: Microsoft \
Product Name: Microsoft 365 Defender \
Minimum Product Version: 6.3.0

This app integrates with Microsoft 365 Defender to execute various generic and investigative actions

## Port Information

The app uses HTTP/ HTTPS protocol for communicating with the Microsoft 365 Defender server. Below
are the default ports used by Splunk SOAR.

| SERVICE NAME | TRANSPORT PROTOCOL | PORT |
|--------------|--------------------|------|
| http | tcp | 80 |
| https | tcp | 443 |

## Explanation of Asset Configuration Parameters

- Tenant ID - It is the Directory ID of the Microsoft Entra ID on the Microsoft
  Azure portal.
- Client ID - It is the Application ID of an application configured in the Microsoft Entra ID.
- Client Secret - It is the secret string used by the application to prove its identity when
  requesting a token. It can be generated for the configured application on the Microsoft Entra ID.
- Non-Interactive Auth - It is used to determine the authentication method. If it is checked then
  non-Interactive auth will be used otherwise interactive auth will be used. Whenever this
  checkbox is toggled then the test connectivity action must be run again.
- Timeout - It is used to make configurable timeout for all actions.

## Explanation of Asset Configuration Parameters for On Poll

- Max Incidents For Polling - In each polling cycle, incidents are fetched for schedule and interval polling based on the provided value (Default 1000). Containers are created per incident.
- Start Time - It is used to filter the incidents based on start time, if nothing is provided, then it will take last week as start time. <br> **NOTE: Start time is used to filter based on lastUpdateDateTime property of incident**
- Filter - It is used to add extra filters on incident properties.

## Explanation of On Poll Behavior

- The default incident order is set to "lastUpdateDateTime," prioritizing the latest incidents as newest.
- The start time parameter value aligns with the lastUpdateDateTime of the incident.
- The maximum incidents parameter functions exclusively with scheduled and interval polling.
- For Example,if the maximum incident parameter is set to 100, the 'on_poll' feature must incorporate up to 100 distinct incidents, based on the provided filter and start time parameter value.

## Configure and set up permissions of the app created on the Microsoft Azure portal

<div style="margin-left: 2em">

#### Create the app

1. Navigate to <https://portal.azure.com> .
1. Log in with a user that has permission to create an app in the Microsoft Entra ID.
1. Select the 'Microsoft Entra ID'.
1. Select the 'App registrations' menu from the left-side panel.
1. Select the 'New Registration' option at the top of the page.
1. In the registration form, choose a name for your application and then click 'Register'.

#### Add permissions

7. Select the 'API Permissions' menu from the left-side panel.

1. Click on 'Add a permission'.

1. Under the 'Select an API' section, select 'APIs my organization uses'.

1. Search for 'Microsoft Graph' keyword in the search box and click on the displayed option for it.

1. Provide the following Delegated and Application permissions to the app.

   - **Application Permissions**

     - SecurityAlert.Read.All
     - SecurityAlert.ReadWrite.All
     - ThreatHunting.Read.All
     - SecurityIncident.Read.All
     - SecurityIncident.ReadWrite.All

   - **Delegated Permissions**

     - SecurityAlert.Read.All
     - SecurityAlert.ReadWrite.All
     - ThreatHunting.Read.All
     - SecurityIncident.Read.All
     - SecurityIncident.ReadWrite.All

1. 'Grant Admin Consent' for it.

1. Again click on 'Add a permission'.

1. Under the 'Select an API' section, select 'Microsoft APIs'.

1. Click on the 'Microsoft Graph' option.

1. Provide the following Delegated permission to the app.

   - **Delegated Permission**

     - offline_access

#### Create a client secret or jump to next section to use Certificate Based Authentication

17. Select the 'Certificates & secrets' menu from the left-side panel.
01. Select 'New client secret' button to open a pop-up window.
01. Provide the description, select an appropriate option for deciding the client secret expiration
    time, and click on the 'Add' button.
01. Click 'Copy to clipboard' to copy the generated secret value and paste it in a safe place. You
    will need it to configure the asset and will not be able to retrieve it later.

#### Using Certificate Based Authentication

21. Select the 'Certificates & secrets' menu from the left-side panel.
01. Select the 'Certificates' tab.
01. Click 'Upload Certificate' and choose a '\*.crt' file that contains the server certificate.
01. Select the 'Thumbprint' for the newly uploaded certificate and copy it somewhere to be
    used when configuring the SOAR app.

#### Copy your application id and tenant id

25. Select the 'Overview' menu from the left-side panel.
01. Copy the **Application (client) ID** and **Directory (tenant) ID** . You will need these to
    configure the SOAR asset.

## Configure the Microsoft 365 Defender SOAR app's asset

When creating an asset for the app,

- Check the checkbox **Non-Interactive Auth** if you want to use Non-Interactive authentication
  mechanism otherwise Interactive auth mechanism will be used.

- Provide the client ID of the app created during the previous step of app creation in the 'Client
  ID' field.

- Provide the client secret of the app created during the previous step of app creation in the
  'Client Secret' field. -or- If using Certificate Based Authenticaion, do not not enter anything
  in this field, instead, complete the next three steps.

- For Certificate Based Authentication only: Provide the 'Certificate Thumbprint' recorded above from Microsoft Entra.

- For Certificate Based Authentication only: Provide the 'Certificate Private Key' (cut and paste the .pem file contents).

- For Certificate Based Authentication only: Ensure the 'Non-Interactive Auth' checkbox is checked.

- Provide the tenant ID of the app created during the previous step of Azure app creation in the
  'Tenant ID' field. For getting the value of tenant ID, navigate to the Microsoft Entra ID; The value displayed in the 'Tenant ID'.

- Save the asset with the above values.

- After saving the asset, a new uneditable field will appear in the 'Asset Settings' tab of the
  configured asset for the Microsoft 365 Defender app on SOAR. Copy the URL mentioned in the 'POST
  incoming for Microsoft 365 Defender to this location' field. Add a suffix '/result' to the URL
  copied in the previous step. The resulting URL looks like the one mentioned below.

  https://\<soar_host>/rest/handler/microsoft365defender\_\<appid>/\<asset_name>/result

- Add the URL created in the earlier step into the 'Redirect URIs' section of the 'Authentication'
  menu for the registered app that was created in the previous steps on the Microsoft Azure
  portal. For the 'Redirect URIs' section, follow the below steps.

  1. Below steps are required only in case of Interactive auth (i.e. If checkbox is unchecked)
  1. Navigate to the 'Microsoft Entra ID' on the Microsoft Azure portal.
  1. Click on the 'App registrations' menu from the left-side panel.
  1. Click on the earlier created app. You can search for the app by name or client ID.
  1. Navigate to the 'Authentication' menu of the app on the left-side panel.
  1. Click on the 'Add a platform' button and select 'Web' from the displayed options.
  1. Enter the URL created in the earlier section in the 'Redirect URIs' text-box.
  1. Select the 'ID tokens' checkbox and click 'Save'.
  1. This will display the 'Redirect URIs' under the 'Web' section displayed on the page.

## Interactive Method to run Test Connectivity

- Here make sure that the 'Non-Interactive Auth' checkbox is unchecked in asset configuration.
- After setting up the asset and user, click the 'TEST CONNECTIVITY' button. A pop-up window will
  be displayed with appropriate test connectivity logs. It will also display a specific URL on
  that pop-up window.
- Open this URL in a separate browser tab. This new tab will redirect to the Microsoft login page
  to complete the login process to grant the permissions to the app.
- Log in using the same Microsoft account that was used to configure the Microsoft 365 Defender
  workflow and the application on the Microsoft Azure Portal. After logging in, review the
  requested permissions listed and click on the 'Accept' button.
- This will display a successful message of 'Code received. Please close this window, the action
  will continue to get new token.' on the browser tab.
- Finally, close the browser tab and come back to the 'Test Connectivity' browser tab. The pop-up
  window should display a 'Test Connectivity Passed' message.

## Non-Interactive Method to run Test Connectivity

- Here make sure that the 'Non-Interactive Auth' checkbox is checked in asset configuration.
- Click on the 'TEST CONNECTIVITY' button, it should run the test connectivity action without any
  user interaction.

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

- state file path on instance: /opt/phantom/local_data/app_states/\<appid>/\<asset_id>\_state.json

#### State file permissions

- File rights: rw-rw-r-- (664) (The Splunk SOAR user should have read and write access for the
  state file)
- File owner: Appropriate Splunk SOAR user

## Notes

- \<appid> - The app ID will be available in the Redirect URI which gets populated in the field
  'POST incoming for Microsoft 365 Defender to this location' when the Microsoft 365 Defender app
  asset is configured e.g.
  https://\<splunk_soar_host>/rest/handler/microsoft365defender\_\<appid>/\<asset_name>/result
- \<asset_id> - The asset ID will be available on the created asset's Splunk SOAR web URL e.g.
  https://\<splunk_soar_host>/apps/\<app_number>/asset/\<asset_id>/

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

[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration \
[on poll](#action-on-poll) - Callback action for the on_poll ingest functionality \
[run query](#action-run-query) - An advanced search query \
[list incidents](#action-list-incidents) - List all the incidents \
[list alerts](#action-list-alerts) - List all the alerts \
[get incident](#action-get-incident) - Retrieve specific incident by its ID \
[update incident](#action-update-incident) - Update the properties of an incident object \
[get alert](#action-get-alert) - Retrieve specific alert by its ID \
[update alert](#action-update-alert) - Update properties of existing alert

## action: 'test connectivity'

Validate the asset configuration for connectivity using supplied configuration

Type: **test** \
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

No Output

## action: 'on poll'

Callback action for the on_poll ingest functionality

Type: **ingest** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**start_time** | optional | Parameter ignored in this app | numeric | |
**end_time** | optional | Parameter ignored in this app | numeric | |
**container_count** | optional | Parameter ignored for schedule/interval polling only | numeric | |
**artifact_count** | optional | Parameter ignored in this app | numeric | |
**container_id** | optional | Parameter ignored in this app | numeric | |

#### Action Output

No Output

## action: 'run query'

An advanced search query

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**query** | required | Query to fetch results | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.query | string | | DeviceProcessEvents | limit 5 |
action_result.data.\*.DeviceId | string | | xxxxx9d48ec4859bd94a25039dcba09f4fd9ac78 |
action_result.data.\*.FileName | string | | test.exe |
action_result.data.\*.InitiatingProcessFileName | string | | powershell.exe |
action_result.data.\*.Timestamp | string | | 2022-06-12T04:24:25.0406516Z |
action_result.data.\*.odata_context | string | | https://test.com/v1.0/$metadata/incidents/$entity |
action_result.data.\*.additionalData.Intent_odata_type | string | | #Int64 |
action_result.data.\*.evidence.\*.odata_type | string | | #test.graph.security.deviceEvidence |
action_result.data.\*.Intent_odata_type | string | | #Int64 |
action_result.summary.total_results | numeric | | 1 |
action_result.message | string | | Total results: 1 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list incidents'

List all the incidents

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**limit** | optional | Maximum number of incidents to return (Defaults to 50) | numeric | |
**offset** | optional | Number of incidents to skip (Defaults to 0) | numeric | |
**filter** | optional | Filter incidents based on property | string | |
**orderby** | optional | Sort the incidents based on property | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.limit | numeric | | 50 |
action_result.parameter.offset | numeric | | 0 |
action_result.parameter.filter | string | | status eq 'active' |
action_result.parameter.orderby | string | | lastUpdateDateTime desc |
action_result.data.\*.assignedTo | string | `email` | testuser@abc.com |
action_result.data.\*.classification | string | | unknown |
action_result.data.\*.comments.\*.comment | string | | Testing comment |
action_result.data.\*.comments.\*.createdByDisplayName | string | | testuser@abc.com |
action_result.data.\*.comments.\*.createdDateTime | string | | 2022-06-08T08:34:40.68416Z |
action_result.data.\*.createdDateTime | string | | 2022-06-13T10:36:05.7Z |
action_result.data.\*.determination | string | | unknown |
action_result.data.\*.displayName | string | | Malware incident on one endpoint |
action_result.data.\*.id | string | `defender incident id` | 145 |
action_result.data.\*.incidentWebUrl | string | `url` | https://test.com/incidents/45?tid=xxxxx670-d7ef-580d-a225-d48057e74df6 |
action_result.data.\*.lastUpdateDateTime | string | | 2022-06-13T12:57:22.3633333Z |
action_result.data.\*.redirectIncidentId | string | `defender incident id` | 48 |
action_result.data.\*.severity | string | `defender severity` | high |
action_result.data.\*.status | string | | active |
action_result.data.\*.tenantId | string | | xxxxx670-d7ef-580d-a225-d48057e74df6 |
action_result.data.\*.summary | string | | |
action_result.data.\*.description | string | | |
action_result.data.\*.lastModifiedBy | string | | API-App:test@test.test.com |
action_result.data.\*.resolvingComment | string | | |
action_result.summary.total_incidents | numeric | | 50 |
action_result.message | string | | Total incidents: 50 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list alerts'

List all the alerts

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**limit** | optional | Maximum number of alerts to return (Defaults to 2000) | numeric | |
**offset** | optional | Number of alerts to skip (Defaults to 0) | numeric | |
**filter** | optional | Filter alerts based on property | string | |
**orderby** | optional | Sort the alerts based on property | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.limit | numeric | | 2000 |
action_result.parameter.filter | string | | status eq 'inProgress' |
action_result.parameter.orderby | string | | lastUpdateDateTime desc |
action_result.parameter.offset | numeric | | 0 |
action_result.data.\*.actorDisplayName | string | | test@abc.com |
action_result.data.\*.alertWebUrl | string | `url` | https://test.com/alerts/xxxxx812122456454120\_-1108217295?tid=test578-c7ee-480d-a225-d4805xxxxxxx |
action_result.data.\*.assignedTo | string | `email` | test@abc.com |
action_result.data.\*.category | string | | SuspiciousActivity |
action_result.data.\*.classification | string | | Test |
action_result.data.\*.comments.\*.comment | string | | initialaccess_type_of_alert_last_option from the dropdown |
action_result.data.\*.comments.\*.createdByDisplayName | string | | Automation |
action_result.data.\*.comments.\*.createdDateTime | string | | 2022-04-08T18:03:49.3223829Z |
action_result.data.\*.createdDateTime | string | | 2022-02-23T11:24:05.6454411Z |
action_result.data.\*.description | string | | Test alert |
action_result.data.\*.detectionSource | string | | customTi |
action_result.data.\*.detectorId | string | | testdb3b-18a9-471b-9ad0-ad80a4cbtest |
action_result.data.\*.determination | string | | Test |
action_result.data.\*.evidence.\*.odata_type | string | | #test.graph.security.deviceEvidence |
action_result.data.\*.evidence.\*.azureAdDeviceId | string | | |
action_result.data.\*.evidence.\*.createdDateTime | string | | 2022-02-23T11:24:05.9366667Z |
action_result.data.\*.evidence.\*.defenderAvStatus | string | | unknown |
action_result.data.\*.evidence.\*.detectionStatus | string | | Test |
action_result.data.\*.evidence.\*.deviceDnsName | string | | testmachine |
action_result.data.\*.evidence.\*.fileDetails.fileName | string | | C:\\Program Files\\Test\\Test\\Application\\Test.exe |
action_result.data.\*.evidence.\*.fileDetails.filePath | string | | C:\\Program Files\\Test\\Test\\Application |
action_result.data.\*.evidence.\*.fileDetails.filePublisher | string | | Test |
action_result.data.\*.evidence.\*.fileDetails.fileSize | numeric | | 77312 |
action_result.data.\*.evidence.\*.fileDetails.issuer | string | | file issuer |
action_result.data.\*.evidence.\*.fileDetails.sha1 | string | `sha1` | xxx8825f6b54238a452e3050d49e8aa50569a6c9 |
action_result.data.\*.evidence.\*.fileDetails.sha256 | string | `sha256` | xxxx4eecd1b9d02a7d6b6d8c9e9c82cc5ce16bfa7c2932944d0bf0fbb13fxxxx |
action_result.data.\*.evidence.\*.fileDetails.signer | string | | signer |
action_result.data.\*.evidence.\*.firstSeenDateTime | string | | 2021-08-30T16:25:37.180194Z |
action_result.data.\*.evidence.\*.healthStatus | string | | inactive |
action_result.data.\*.evidence.\*.imageFile.fileName | string | | powershell.exe |
action_result.data.\*.evidence.\*.imageFile.filePath | string | | c:\\windows\\system32\\windowspowershell\\v1.0 |
action_result.data.\*.evidence.\*.imageFile.filePublisher | string | | test publisher |
action_result.data.\*.evidence.\*.imageFile.fileSize | numeric | | 99912 |
action_result.data.\*.evidence.\*.imageFile.issuer | string | | test issuer |
action_result.data.\*.evidence.\*.imageFile.sha1 | string | `sha1` | xxxx9bb316e30ae1a3494ac5b0624f6bea1bxxxx |
action_result.data.\*.evidence.\*.imageFile.sha256 | string | `sha256` | xxx14d42706fe215501044acd85a32d58aaef1419d404fddfa5d3b48f66ccxxx |
action_result.data.\*.evidence.\*.imageFile.signer | string | | test signer |
action_result.data.\*.evidence.\*.ipAddress | string | `ip` | 8.8.8.8 |
action_result.data.\*.evidence.\*.loggedOnUsers.\*.accountName | string | | test |
action_result.data.\*.evidence.\*.loggedOnUsers.\*.domainName | string | | TESTMACHINE |
action_result.data.\*.evidence.\*.mdeDeviceId | string | | xxxx84aa7ef0294f733b7b6e9499439e433axxxx |
action_result.data.\*.evidence.\*.onboardingStatus | string | | onboarded |
action_result.data.\*.evidence.\*.osBuild | numeric | | 19044 |
action_result.data.\*.evidence.\*.osPlatform | string | | Windows10 |
action_result.data.\*.evidence.\*.parentProcessCreationDateTime | string | | 2022-03-09T19:52:51Z |
action_result.data.\*.evidence.\*.parentProcessId | numeric | | 7968 |
action_result.data.\*.evidence.\*.parentProcessImageFile | string | | TestFile |
action_result.data.\*.evidence.\*.parentProcessImageFile.fileName | string | | Test.exe |
action_result.data.\*.evidence.\*.parentProcessImageFile.filePath | string | | C:\\Program Files\\Test\\Test\\Application\\Test.exe |
action_result.data.\*.evidence.\*.parentProcessImageFile.filePublisher | string | | Test publisher |
action_result.data.\*.evidence.\*.parentProcessImageFile.fileSize | numeric | | 36557800 |
action_result.data.\*.evidence.\*.parentProcessImageFile.issuer | string | | test issuer |
action_result.data.\*.evidence.\*.parentProcessImageFile.sha1 | string | `sha1` | xxxx9bb316e30ae1a3494ac5b0624f6bea1bxxxx |
action_result.data.\*.evidence.\*.parentProcessImageFile.sha256 | string | `sha256` | xxx14d42706fe215501044acd85a32d58aaef1419d404fddfa5d3b48f66ccxxx |
action_result.data.\*.evidence.\*.parentProcessImageFile.signer | string | | test signer |
action_result.data.\*.evidence.\*.processCommandLine | string | | powershell.exe -ExecutionPolicy AllSigned -NoProfile -NonInteractive |
action_result.data.\*.evidence.\*.processCreationDateTime | string | | 2022-03-09T19:53:01Z |
action_result.data.\*.evidence.\*.processId | numeric | | 6240 |
action_result.data.\*.evidence.\*.rbacGroupId | numeric | | 73 |
action_result.data.\*.evidence.\*.rbacGroupName | string | | UnassignedGroup |
action_result.data.\*.evidence.\*.registryHive | string | | HKEY_LOCAL_MACHINE |
action_result.data.\*.evidence.\*.registryKey | string | | SOFTWARE\\test\\Windows NT\\CurrentVersion\\Image File Execution Options\\Login.scr |
action_result.data.\*.evidence.\*.registryValue | string | | 43-00-3A-00-5C-00-57-00-69-01-6E-10-64-00-6F-00-77-00-73-00-5C-00-53-00-79-00-73-00-74-00-65-00-6D-00-33-00-32-00-5C-00-63-00-61-00-6C-00-63-00-2E-00-65-00-78-00-65-00-00-00 |
action_result.data.\*.evidence.\*.registryValueName | string | | Debugger |
action_result.data.\*.evidence.\*.registryValueType | string | | Unknown |
action_result.data.\*.evidence.\*.remediationStatus | string | | prevented |
action_result.data.\*.evidence.\*.remediationStatusDetails | string | | status details |
action_result.data.\*.evidence.\*.riskScore | string | | high |
action_result.data.\*.evidence.\*.url | string | `url` | test.com |
action_result.data.\*.evidence.\*.userAccount | string | | |
action_result.data.\*.evidence.\*.userAccount.accountName | string | | local service |
action_result.data.\*.evidence.\*.userAccount.azureAdUserId | string | | xxxxxxx |
action_result.data.\*.evidence.\*.userAccount.domainName | string | | nt authority |
action_result.data.\*.evidence.\*.userAccount.userPrincipalName | string | | test |
action_result.data.\*.evidence.\*.userAccount.userSid | string | | S-1-5-19 |
action_result.data.\*.evidence.\*.verdict | string | | unknown |
action_result.data.\*.evidence.\*.version | string | | X1HX |
action_result.data.\*.firstActivityDateTime | string | | 2022-02-23T11:22:20.1835364Z |
action_result.data.\*.id | string | `defender alert id` | xx637812122456454120\_-11082172xx |
action_result.data.\*.incidentId | string | `defender incident id` | 42 |
action_result.data.\*.incidentWebUrl | string | `url` | https://test.com/incidents/42?tid=xxxxc578-c7ee-480d-a225-d48057e7xxxx |
action_result.data.\*.lastActivityDateTime | string | | 2022-02-23T11:22:20.1835364Z |
action_result.data.\*.lastUpdateDateTime | string | | 2022-02-24T03:52:41.7933333Z |
action_result.data.\*.providerAlertId | string | `defender alert id` | xxxx7812122456454120\_-1108217xxx |
action_result.data.\*.recommendedActions | string | | A. Validate the alert and scope the suspected breach.<br>1. Find related machines, network addresses, and files in the incident graph.<br>2. Check for other suspicious activities in the machine timeline.<br>3. Locate unfamiliar processes in the process tree. Check files for prevalence, their locations, and digital signatures.<br>4. Submit relevant files for deep analysis and review file behaviors. <br>5. Identify unusual system activity with system owners. <br><br>B. If you have validated the alert, contain and mitigate the breach.<br>1. Record relevant artifacts, including those you need in mitigation rules.<br>2. Stop suspicious processes. Block prevalent malware files across the network.<br>3. Isolate affected machines.<br>4. Identify potentially compromised accounts. If necessary, reset passwords and decommission accounts.<br>5. Block relevant emails, websites, and IP addresses. Remove attack emails from mailboxes.<br>6. Update antimalware signatures and run full scans. <br>7. Deploy the latest security updates for Windows, web browsers, and other applications.<br><br>C. Contact your incident response team, or contact test support for forensic analysis and remediation services.<br><br>Disclaimer: These guidelines are for reference only. They do not guarantee successful threat removal. |
action_result.data.\*.resolvedDateTime | string | | 2022-02-23T11:24:05.6454411Z |
action_result.data.\*.serviceSource | string | | TestEndpoint |
action_result.data.\*.severity | string | `defender severity` | medium |
action_result.data.\*.status | string | | new |
action_result.data.\*.tenantId | string | | xxxxc578-c7ee-480d-a225-d48057e74df5 |
action_result.data.\*.threatDisplayName | string | | threat |
action_result.data.\*.threatFamilyName | string | | threat |
action_result.data.\*.title | string | | Test alert |
action_result.data.\*.evidence.\*.vmMetadata.vmId | string | | test363-806f-4d19-9b75-9ec2f59test |
action_result.data.\*.evidence.\*.vmMetadata.resourceId | string | | /subscriptions/test906-0000-test-test-test9test70/resourceGroups/PLUGINFRAMEWORK/providers/test.Compute/virtualMachines/TEST-ID |
action_result.data.\*.evidence.\*.vmMetadata.cloudProvider | string | | azure |
action_result.data.\*.evidence.\*.vmMetadata.subscriptionId | string | | |
action_result.data.\*.evidence.\*.lastIpAddress | string | | 10.0.2.15 |
action_result.data.\*.evidence.\*.lastExternalIpAddress | string | | |
action_result.data.\*.evidence.\*.resourceId | string | | /subscriptions/test7906-0000-test-test-1testa8test0/resourceGroups/pluginframework/providers/test.Compute/virtualMachines/test-identity |
action_result.data.\*.evidence.\*.resourceName | string | | test-resource |
action_result.data.\*.evidence.\*.resourceType | string | | Virtual Machine |
action_result.data.\*.productName | string | | Test Platform for Cloud |
action_result.data.\*.alertPolicyId | string | | |
action_result.data.\*.additionalData.Intent | numeric | | 8193 |
action_result.data.\*.additionalData.AlertUri | string | | https://test.com/#blade/testa/AlertBlade/alertId/test35test123461_test1230-7777-test-test-testd4test7/subscriptionId/test906-test-dddd-test-test9a8test/resourceGroup/pluginframework/referencedFrom/alertDeepLink/location/centralus |
action_result.data.\*.additionalData.TimeGenerated | string | | 2024-02-08T05:11:57.256Z |
action_result.data.\*.additionalData.Intent_odata_type | string | | #Int64 |
action_result.data.\*.additionalData.ProcessingEndTime | string | | 2024-02-08T05:11:57.6847793Z |
action_result.data.\*.additionalData.Attacker source IP | string | | IP Address: 45.141.85.1 |
action_result.data.\*.additionalData.ProductComponentName | string | | Servers |
action_result.data.\*.additionalData.WorkspaceResourceGroup | string | | defaultresourcegroup-eus |
action_result.data.\*.additionalData.Activity end time (UTC) | string | | 2024/02/08 04:59:22.9525229 |
action_result.data.\*.additionalData.EffectiveSubscriptionId | string | | test7906-2c22-4d91-98aa-180d9a85test |
action_result.data.\*.additionalData.WorkspaceSubscriptionId | string | | test7906-2c22-4d91-98aa-180d9a85test |
action_result.data.\*.additionalData.EffectiveAzureResourceId | string | | /subscriptions/test7906-2c22-4d91-98aa-180d9a85test/resourceGroups/pluginframework/providers/test.Compute/virtualMachines/test-id |
action_result.data.\*.additionalData.OriginalAlertProductName | string | | Detection-WarmPathV2 |
action_result.data.\*.additionalData.Activity start time (UTC) | string | | 2024/02/08 04:01:15.2808538 |
action_result.data.\*.additionalData.OriginalAlertProviderName | string | | Test Platform for Cloud |
action_result.data.\*.additionalData.Was RDP session initiated | string | | No |
action_result.data.\*.additionalData.Attacker source computer name | string | | Unknown |
action_result.data.\*.additionalData.Number of failed authentication attempts to host | string | | 59 |
action_result.data.\*.additionalData.Top accounts with failed sign in attempts (count) | string | | AdministratÃ¶r (5), user0 (4), Administrateur (4), Rendszergazda (4), audit (4), tester (3), JÃ¤rjestelmÃ¤nvalvoja (3), Administrator (3), audit1 (3), audit0 (3) |
action_result.data.\*.additionalData.Number of existing accounts used by source to sign in | string | | 1 |
action_result.data.\*.additionalData.Number of nonexistent accounts used by source to sign in | string | | 20 |
action_result.data.\*.evidence.\*.vmMetadata | string | | |
action_result.data.\*.evidence.\*.stream | string | | |
action_result.data.\*.evidence.\*.userAccount.displayName | string | | Herman Edwards |
action_result.data.\*.evidence.\*.location.city | string | | Denver |
action_result.data.\*.evidence.\*.location.state | string | | Colorado |
action_result.data.\*.evidence.\*.location.latitude | numeric | | 39.75263 |
action_result.data.\*.evidence.\*.location.longitude | numeric | | -104.99809 |
action_result.data.\*.evidence.\*.location.countryName | string | | |
action_result.data.\*.evidence.\*.countryLetterCode | string | | US |
action_result.data.\*.additionalData | string | | |
action_result.data.\*.evidence.\*.displayName | string | | Herman Edwards |
action_result.data.\*.evidence.\*.primaryAddress | string | | test@test.com |
action_result.data.\*.evidence.\*.location | string | | |
action_result.summary.total_alerts | numeric | | 2 |
action_result.message | string | | Total alerts: 2 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |
action_result.data.\*.evidence.\*.hostName | string | | |
action_result.data.\*.evidence.\*.ntDomain | string | | |
action_result.data.\*.evidence.\*.dnsDomain | string | | |
action_result.data.\*.evidence.\*.@odata.type | string | | #test.graph.security.deviceEvidence |
action_result.data.\*.additionalData.Intent@odata.type | string | | #Int64 |
action_result.data.\*.Intent_odata_type | string | | #Int64 |

## action: 'get incident'

Retrieve specific incident by its ID

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**incident_id** | required | ID of the incident | string | `defender incident id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.incident_id | string | `defender incident id` | 48 |
action_result.data.\*.assignedTo | string | `email` | testuser@abc.com |
action_result.data.\*.classification | string | | unknown |
action_result.data.\*.comments.\*.comment | string | | |
action_result.data.\*.comments.\*.createdByDisplayName | string | | testuser@abc.com |
action_result.data.\*.comments.\*.createdDateTime | string | | 2022-06-08T08:34:40.68416Z |
action_result.data.\*.createdDateTime | string | | 2022-06-13T10:36:05.7Z |
action_result.data.\*.determination | string | | unknown |
action_result.data.\*.displayName | string | | Test alert on one endpoint |
action_result.data.\*.id | string | `defender incident id` | 145 |
action_result.data.\*.incidentWebUrl | string | `url` | https://test.com/incidents/45?tid=xxxxx670-d7ef-580d-a225-d48057e74df6 |
action_result.data.\*.lastUpdateDateTime | string | | 2022-06-13T12:57:22.3633333Z |
action_result.data.\*.redirectIncidentId | string | `defender incident id` | 48 |
action_result.data.\*.severity | string | `defender severity` | high |
action_result.data.\*.status | string | | active |
action_result.data.\*.tags.\* | string | | |
action_result.data.\*.tenantId | string | `microsoft tenantid` | xxxxx670-d7ef-580d-a225-d48057e74df6 |
action_result.data.\*.summary | string | | |
action_result.data.\*.description | string | | |
action_result.data.\*.odata_context | string | | https://test.com/v1.0/$metadata/incidents/$entity |
action_result.data.\*.lastModifiedBy | string | | API-App:test@test.com |
action_result.data.\*.resolvingComment | string | | |
action_result.summary | string | | |
action_result.message | string | | Successfully retrieved the incident |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |
action_result.data.\*.@odata.context | string | | https://graph.test.com/v1.0/$metadata#security/incidents/$entity |

## action: 'update incident'

Update the properties of an incident object

Type: **generic** \
Read only: **False**

In this `SecurityIncident.ReadWrite.All` delegated or application permission is required. One of the parameters `status`, `assign_to`, `classification` or `determination` must be specified; otherwise, the action fails.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**incident_id** | required | ID of the incident | string | `defender incident id` |
**status** | optional | The status of the incident | string | |
**assign_to** | optional | Owner of the incident, or null if no owner is assigned. Free editable text | string | |
**classification** | optional | The specification for the incident | string | |
**determination** | optional | Specifies the determination of the incident | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.incident_id | string | `defender incident id` | 48 |
action_result.parameter.determination | string | | Malware |
action_result.parameter.classification | string | | True Positive |
action_result.parameter.assign_to | string | | testuser |
action_result.parameter.status | string | | Active |
action_result.data.\*.summary | string | | |
action_result.data.\*.severity | string | | medium |
action_result.data.\*.tenantId | string | | testc578-c7ee-480d-atest-d48057etest |
action_result.data.\*.assignedTo | string | | |
action_result.data.\*.description | string | | |
action_result.data.\*.displayName | string | | Suspicious authentication activity on one endpoint |
action_result.data.\*.determination | string | | unknown |
action_result.data.\*.odata_context | string | | https://test.com/v1.0/$metadata#/incidents/$entity |
action_result.data.\*.classification | string | | unknownFutureValue |
action_result.data.\*.incidentWebUrl | string | | https://test.com/incidents/308?tid=testc578-c7ee-480d-atest-d48057etest |
action_result.data.\*.lastModifiedBy | string | | Automation |
action_result.data.\*.createdDateTime | string | | 2024-01-07T05:12:17.0266667Z |
action_result.data.\*.resolvingComment | string | | |
action_result.data.\*.lastUpdateDateTime | string | | 2024-07-04T09:44:46.7112452Z |
action_result.data.\*.redirectIncidentId | string | | |
action_result.data.\*.id | string | `defender incident id` | 145 |
action_result.data.\*.status | string | | active |
action_result.status | string | | success failed |
action_result.summary | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |
action_result.data.\*.@odata.context | string | | https://graph.test.com/v1.0/$metadata#security/incidents/$entity |

## action: 'get alert'

Retrieve specific alert by its ID

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**alert_id** | required | ID of the alert | string | `defender alert id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.alert_id | string | `defender alert id` | xxxxx812122456454120\_-11082xxxxx |
action_result.data.\*.actorDisplayName | string | | test@abc.com |
action_result.data.\*.alertWebUrl | string | | https://test.com/alerts/xxxxx812122456454120\_-1108217295?tid=testc578-c7ee-480d-a225-d4805xxxxxxx |
action_result.data.\*.assignedTo | string | `email` | test@abc.com |
action_result.data.\*.category | string | | SuspiciousActivity |
action_result.data.\*.classification | string | | Test |
action_result.data.\*.comments.\*.comment | string | | initialaccess_type_of_alert_last_option from the dropdown |
action_result.data.\*.comments.\*.createdByDisplayName | string | | Automation |
action_result.data.\*.comments.\*.createdDateTime | string | | 2022-04-08T18:03:49.3223829Z |
action_result.data.\*.createdDateTime | string | | 2022-02-23T11:24:05.6454411Z |
action_result.data.\*.description | string | | Test alert |
action_result.data.\*.detectionSource | string | | customTi |
action_result.data.\*.detectorId | string | | 360fdb3b-18a9-471b-9ad0-ad80a4cbcb02 |
action_result.data.\*.determination | string | | Test |
action_result.data.\*.evidence.\*.odata_type | string | | #test.graph.security.deviceEvidence |
action_result.data.\*.evidence.\*.azureAdDeviceId | string | | |
action_result.data.\*.evidence.\*.createdDateTime | string | | 2022-02-23T11:24:05.9366667Z |
action_result.data.\*.evidence.\*.defenderAvStatus | string | | unknown |
action_result.data.\*.evidence.\*.detectionStatus | string | | Test |
action_result.data.\*.evidence.\*.deviceDnsName | string | | testmachine |
action_result.data.\*.evidence.\*.fileDetails.fileName | string | | C:\\Program Files\\Test\\Test\\Application\\Test.exe |
action_result.data.\*.evidence.\*.fileDetails.filePath | string | | C:\\Program Files\\Test\\Test\\Application |
action_result.data.\*.evidence.\*.fileDetails.filePublisher | string | | Test |
action_result.data.\*.evidence.\*.fileDetails.fileSize | numeric | | 77312 |
action_result.data.\*.evidence.\*.fileDetails.issuer | string | | file issuer |
action_result.data.\*.evidence.\*.fileDetails.sha1 | string | `sha1` | xxx8825f6b54238a452e3050d49e8aa50569a6c9 |
action_result.data.\*.evidence.\*.fileDetails.sha256 | string | `sha256` | 7db34eecd1b9d02a7d6b6d8c9e9c82cc5ce16bfa7c2932944d0bf0fbb13f5bc6 |
action_result.data.\*.evidence.\*.fileDetails.signer | string | | signer |
action_result.data.\*.evidence.\*.firstSeenDateTime | string | | 2021-08-30T16:25:37.180194Z |
action_result.data.\*.evidence.\*.healthStatus | string | | inactive |
action_result.data.\*.evidence.\*.imageFile.fileName | string | | powershell.exe |
action_result.data.\*.evidence.\*.imageFile.filePath | string | | c:\\windows\\system32\\windowspowershell\\v1.0 |
action_result.data.\*.evidence.\*.imageFile.filePublisher | string | | test publisher |
action_result.data.\*.evidence.\*.imageFile.fileSize | numeric | | 99912 |
action_result.data.\*.evidence.\*.imageFile.issuer | string | | test issuer |
action_result.data.\*.evidence.\*.imageFile.sha1 | string | `sha1` | xxxx9bb316e30ae1a3494ac5b0624f6bea1bxxxx |
action_result.data.\*.evidence.\*.imageFile.sha256 | string | `sha256` | xxx14d42706fe215501044acd85a32d58aaef1419d404fddfa5d3b48f66ccxxx |
action_result.data.\*.evidence.\*.imageFile.signer | string | | test signer |
action_result.data.\*.evidence.\*.ipAddress | string | `ip` | 8.8.8.8 |
action_result.data.\*.evidence.\*.loggedOnUsers.\*.accountName | string | | test |
action_result.data.\*.evidence.\*.loggedOnUsers.\*.domainName | string | | TESTMACHINE |
action_result.data.\*.evidence.\*.mdeDeviceId | string | | xxxx84aa7ef0294f733b7b6e9499439e433axxxx |
action_result.data.\*.evidence.\*.onboardingStatus | string | | onboarded |
action_result.data.\*.evidence.\*.osBuild | numeric | | 19044 |
action_result.data.\*.evidence.\*.osPlatform | string | | Windows10 |
action_result.data.\*.evidence.\*.parentProcessCreationDateTime | string | | 2022-03-09T19:52:51Z |
action_result.data.\*.evidence.\*.parentProcessId | numeric | | 7968 |
action_result.data.\*.evidence.\*.parentProcessImageFile | string | | TestFile |
action_result.data.\*.evidence.\*.parentProcessImageFile.fileName | string | | Test.exe |
action_result.data.\*.evidence.\*.parentProcessImageFile.filePath | string | | C:\\Program Files\\Test\\Test\\Application\\Test.exe |
action_result.data.\*.evidence.\*.parentProcessImageFile.filePublisher | string | | Test publisher |
action_result.data.\*.evidence.\*.parentProcessImageFile.fileSize | numeric | | 36557800 |
action_result.data.\*.evidence.\*.parentProcessImageFile.issuer | string | | test issuer |
action_result.data.\*.evidence.\*.parentProcessImageFile.sha1 | string | `sha1` | xxxx9bb316e30ae1a3494ac5b0624f6bea1bxxxx |
action_result.data.\*.evidence.\*.parentProcessImageFile.sha256 | string | `sha256` | xxx14d42706fe215501044acd85a32d58aaef1419d404fddfa5d3b48f66ccxxx |
action_result.data.\*.evidence.\*.parentProcessImageFile.signer | string | | test signer |
action_result.data.\*.evidence.\*.processCommandLine | string | | powershell.exe -ExecutionPolicy AllSigned -NoProfile -NonInteractive |
action_result.data.\*.evidence.\*.processCreationDateTime | string | | 2022-03-09T19:53:01Z |
action_result.data.\*.evidence.\*.processId | numeric | | 6240 |
action_result.data.\*.evidence.\*.rbacGroupId | numeric | | 73 |
action_result.data.\*.evidence.\*.rbacGroupName | string | | UnassignedGroup |
action_result.data.\*.evidence.\*.registryHive | string | | HKEY_LOCAL_MACHINE |
action_result.data.\*.evidence.\*.registryKey | string | | SOFTWARE\\test\\Windows NT\\CurrentVersion\\Image File Execution Options\\Login.scr |
action_result.data.\*.evidence.\*.registryValue | string | | 43-00-3A-00-5C-00-57-00-69-01-6E-10-64-00-6F-00-77-00-73-00-5C-00-53-00-79-00-73-00-74-00-65-00-6D-00-33-00-32-00-5C-00-63-00-61-00-6C-00-63-00-2E-00-65-00-78-00-65-00-00-00 |
action_result.data.\*.evidence.\*.registryValueName | string | | Debugger |
action_result.data.\*.evidence.\*.registryValueType | string | | Unknown |
action_result.data.\*.evidence.\*.remediationStatus | string | | prevented |
action_result.data.\*.evidence.\*.remediationStatusDetails | string | | status details |
action_result.data.\*.evidence.\*.riskScore | string | | high |
action_result.data.\*.evidence.\*.url | string | `url` | test.com |
action_result.data.\*.evidence.\*.userAccount | string | | |
action_result.data.\*.evidence.\*.userAccount.accountName | string | | local service |
action_result.data.\*.evidence.\*.userAccount.azureAdUserId | string | | xxxxxxx |
action_result.data.\*.evidence.\*.userAccount.domainName | string | | nt authority |
action_result.data.\*.evidence.\*.userAccount.userPrincipalName | string | | test |
action_result.data.\*.evidence.\*.userAccount.userSid | string | | S-1-5-19 |
action_result.data.\*.evidence.\*.verdict | string | | unknown |
action_result.data.\*.evidence.\*.version | string | | X1HX |
action_result.data.\*.firstActivityDateTime | string | | 2022-02-23T11:22:20.1835364Z |
action_result.data.\*.id | string | `defender alert id` | xx637812122456454120\_-11082172xx |
action_result.data.\*.incidentId | string | `defender incident id` | 42 |
action_result.data.\*.incidentWebUrl | string | `url` | https://test.com/incidents/42?tid=xxxxc578-c7ee-480d-a225-d48057e7xxxx |
action_result.data.\*.lastActivityDateTime | string | | 2022-02-23T11:22:20.1835364Z |
action_result.data.\*.lastUpdateDateTime | string | | 2022-02-24T03:52:41.7933333Z |
action_result.data.\*.providerAlertId | string | `defender alert id` | xxxx7812122456454120\_-1108217xxx |
action_result.data.\*.recommendedActions | string | | A. Validate the alert and scope the suspected breach.<br>1. Find related machines, network addresses, and files in the incident graph.<br>2. Check for other suspicious activities in the machine timeline.<br>3. Locate unfamiliar processes in the process tree. Check files for prevalence, their locations, and digital signatures.<br>4. Submit relevant files for deep analysis and review file behaviors. <br>5. Identify unusual system activity with system owners. <br><br>B. If you have validated the alert, contain and mitigate the breach.<br>1. Record relevant artifacts, including those you need in mitigation rules.<br>2. Stop suspicious processes. Block prevalent malware files across the network.<br>3. Isolate affected machines.<br>4. Identify potentially compromised accounts. If necessary, reset passwords and decommission accounts.<br>5. Block relevant emails, websites, and IP addresses. Remove attack emails from mailboxes.<br>6. Update antimalware signatures and run full scans. <br>7. Deploy the latest security updates for Windows, web browsers, and other applications.<br><br>C. Contact your incident response team, or contact test support for forensic analysis and remediation services.<br><br>Disclaimer: These guidelines are for reference only. They do not guarantee successful threat removal. |
action_result.data.\*.resolvedDateTime | string | | 2022-02-23T11:24:05.6454411Z |
action_result.data.\*.serviceSource | string | | TestEndpoint |
action_result.data.\*.severity | string | `defender severity` | medium |
action_result.data.\*.status | string | | new |
action_result.data.\*.tenantId | string | | xxxxc578-c7ee-480d-a225-d48057e74df5 |
action_result.data.\*.threatDisplayName | string | | threat |
action_result.data.\*.threatFamilyName | string | | threat |
action_result.data.\*.title | string | | Test alert |
action_result.summary | string | | |
action_result.message | string | | Successfully retrieved the alert |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |
action_result.data.\*.evidence.\*.hostName | string | | |
action_result.data.\*.evidence.\*.ntDomain | string | | |
action_result.data.\*.evidence.\*.dnsDomain | string | | |
action_result.data.\*.evidence.\*.vmMetadata | string | | |
action_result.data.\*.evidence.\*.@odata.type | string | | #test.graph.security.deviceEvidence |
action_result.data.\*.evidence.\*.lastIpAddress | string | | |
action_result.data.\*.evidence.\*.lastExternalIpAddress | string | | |
action_result.data.\*.evidence.\*.resourceId | string | | /subscriptions/test7906-0000-test-test-1testa8test0/resourceGroups/pluginframework/providers/test.Compute/virtualMachines/PluginFrameworkWinTargetVM |
action_result.data.\*.evidence.\*.resourceName | string | | PluginFrameworkWinTargetVM |
action_result.data.\*.evidence.\*.resourceType | string | | Virtual Machine |
action_result.data.\*.productName | string | | Test Platform for Cloud |
action_result.data.\*.alertPolicyId | string | | |
action_result.data.\*.odata_context | string | | https://graph.test.com/v1.0/$metadata#security/alerts_v2/$entity |
action_result.data.\*.@odata.context | string | | https://graph.test.com/v1.0/$metadata#security/alerts_v2/$entity |
action_result.data.\*.additionalData.Intent | numeric | | 8193 |
action_result.data.\*.additionalData.AlertUri | string | | https://test.com/#blade/testa/AlertBlade/alertId/test35test123461_test1230-7777-test-test-testd4test7/subscriptionId/test906-test-dddd-test-test9a8test/resourceGroup/pluginframework/referencedFrom/alertDeepLink/location/centralus |
action_result.data.\*.additionalData.TimeGenerated | string | | 2024-05-16T00:12:00.174Z |
action_result.data.\*.additionalData.Intent@odata.type | string | | #Int64 |
action_result.data.\*.additionalData.ProcessingEndTime | string | | 2024-05-16T00:12:02.7000014Z |
action_result.data.\*.additionalData.Attacker source IP | string | | IP Address: 177.12.214.64 |
action_result.data.\*.additionalData.ProductComponentName | string | | Servers |
action_result.data.\*.additionalData.WorkspaceResourceGroup | string | | defaultresourcegroup-eus |
action_result.data.\*.additionalData.Activity end time (UTC) | string | | 2024/05/15 23:59:49.1923578 |
action_result.data.\*.additionalData.EffectiveSubscriptionId | string | | 4c357906-2c22-4d91-98aa-180d9a85a370 |
action_result.data.\*.additionalData.WorkspaceSubscriptionId | string | | 4c357906-2c22-4d91-98aa-180d9a85a370 |
action_result.data.\*.additionalData.EffectiveAzureResourceId | string | | /subscriptions/test7906-2c22-4d91-98aa-180d9a85test/resourceGroups/pluginframework/providers/test.Compute/virtualMachines/test-id |
action_result.data.\*.additionalData.OriginalAlertProductName | string | | Detection-WarmPathV2 |
action_result.data.\*.additionalData.Activity start time (UTC) | string | | 2024/05/15 23:00:07.9736272 |
action_result.data.\*.additionalData.OriginalAlertProviderName | string | | Test Platform for Cloud |
action_result.data.\*.additionalData.Was RDP session initiated | string | | No |
action_result.data.\*.additionalData.Attacker source computer name | string | | Unknown |
action_result.data.\*.additionalData.Number of failed authentication attempts to host | string | | 23 |
action_result.data.\*.additionalData.Top accounts with failed sign in attempts (count) | string | | admin (2), ARAXI (1), user1 (1), daveb231 (1), Sp3 (1), DefaultAccount (1), 29zj (1), Adminisrator (1), aselsan (1), backup (1) |
action_result.data.\*.additionalData.Number of existing accounts used by source to sign in | string | | 1 |
action_result.data.\*.additionalData.Number of nonexistent accounts used by source to sign in | string | | 21 |
action_result.data.\*.Intent_odata_type | string | | #Int64 |
action_result.data.\*.evidence.\*.vmMetadata.vmId | string | | e3d18363-806f-4d19-9b75-9ec2f5953cd4 |
action_result.data.\*.evidence.\*.vmMetadata.resourceId | string | | /subscriptions/test906-0000-test-test-test9test70/resourceGroups/PLUGINFRAMEWORK/providers/test.Compute/virtualMachines/TEST-ID |
action_result.data.\*.evidence.\*.vmMetadata.cloudProvider | string | | azure |
action_result.data.\*.evidence.\*.vmMetadata.subscriptionId | string | | |

## action: 'update alert'

Update properties of existing alert

Type: **generic** \
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**alert_id** | required | ID of the alert | string | `defender alert id` |
**status** | optional | Specifies the status of the alert | string | |
**assign_to** | optional | Owner of the alert | string | `email` |
**classification** | optional | Specifies the specification of the alert | string | |
**determination** | optional | Specifies the determination of the alert | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.alert_id | string | `defender alert id` | xx637812122456454120\_-11082172xx |
action_result.parameter.assign_to | string | `email` | test@abc.com |
action_result.parameter.classification | string | | Unknown |
action_result.parameter.determination | string | | Other |
action_result.parameter.status | string | | New |
action_result.data.\*.odata_context | string | `url` | https://test.com/beta/$metadata#security/alerts_v2/$entity |
action_result.data.\*.mitreTechniques.\* | string | | T1546.008 |
action_result.data.\*.evidence.\*.tags.\* | string | | testtag |
action_result.data.\*.evidence.\*.vmMetadata.vmId | string | | |
action_result.data.\*.evidence.\*.vmMetadata.resourceId | string | | |
action_result.data.\*.evidence.\*.vmMetadata.cloudProvider | string | | |
action_result.data.\*.evidence.\*.vmMetadata.subscriptionId | string | | |
action_result.data.\*.actorDisplayName | string | | test@abc.com |
action_result.data.\*.alertWebUrl | string | `url` | https://test.com/alerts/xxxxx812122456454120\_-1108217295?tid=a417c578-c7ee-480d-a225-d4805xxxxxxx |
action_result.data.\*.assignedTo | string | `email` | test@abc.com |
action_result.data.\*.category | string | | SuspiciousActivity |
action_result.data.\*.classification | string | | Test |
action_result.data.\*.comments.\*.comment | string | | initialaccess_type_of_alert_last_option from the dropdown |
action_result.data.\*.comments.\*.createdByDisplayName | string | | Automation |
action_result.data.\*.comments.\*.createdDateTime | string | | 2022-04-08T18:03:49.3223829Z |
action_result.data.\*.createdDateTime | string | | 2022-02-23T11:24:05.6454411Z |
action_result.data.\*.description | string | | Test alert |
action_result.data.\*.detectionSource | string | | customTi |
action_result.data.\*.detectorId | string | | 360fdb3b-18a9-471b-9ad0-ad80a4cbcb02 |
action_result.data.\*.determination | string | | Test |
action_result.data.\*.evidence.\*.odata_type | string | | #test.graph.security.deviceEvidence |
action_result.data.\*.evidence.\*.azureAdDeviceId | string | | |
action_result.data.\*.evidence.\*.createdDateTime | string | | 2022-02-23T11:24:05.9366667Z |
action_result.data.\*.evidence.\*.defenderAvStatus | string | | unknown |
action_result.data.\*.evidence.\*.detectionStatus | string | | Test |
action_result.data.\*.evidence.\*.deviceDnsName | string | | testmachine |
action_result.data.\*.evidence.\*.fileDetails.fileName | string | | C:\\Program Files\\Test\\Test\\Application\\Test.exe |
action_result.data.\*.evidence.\*.fileDetails.filePath | string | | C:\\Program Files\\Test\\Test\\Application |
action_result.data.\*.evidence.\*.fileDetails.filePublisher | string | | Test |
action_result.data.\*.evidence.\*.fileDetails.fileSize | numeric | | 77312 |
action_result.data.\*.evidence.\*.fileDetails.issuer | string | | file issuer |
action_result.data.\*.evidence.\*.fileDetails.sha1 | string | `sha1` | xxx8825f6b54238a452e3050d49e8aa50569a6c9 |
action_result.data.\*.evidence.\*.fileDetails.sha256 | string | `sha256` | 7db34eecd1b9d02a7d6b6d8c9e9c82cc5ce16bfa7c2932944d0bf0fbb13f5bc6 |
action_result.data.\*.evidence.\*.fileDetails.signer | string | | signer |
action_result.data.\*.evidence.\*.firstSeenDateTime | string | | 2021-08-30T16:25:37.180194Z |
action_result.data.\*.evidence.\*.healthStatus | string | | inactive |
action_result.data.\*.evidence.\*.imageFile.fileName | string | | powershell.exe |
action_result.data.\*.evidence.\*.imageFile.filePath | string | | c:\\windows\\system32\\windowspowershell\\v1.0 |
action_result.data.\*.evidence.\*.imageFile.filePublisher | string | | test publisher |
action_result.data.\*.evidence.\*.imageFile.fileSize | numeric | | 99912 |
action_result.data.\*.evidence.\*.imageFile.issuer | string | | test issuer |
action_result.data.\*.evidence.\*.imageFile.sha1 | string | `sha1` | xxxx9bb316e30ae1a3494ac5b0624f6bea1bxxxx |
action_result.data.\*.evidence.\*.imageFile.sha256 | string | `sha256` | xxx14d42706fe215501044acd85a32d58aaef1419d404fddfa5d3b48f66ccxxx |
action_result.data.\*.evidence.\*.imageFile.signer | string | | test signer |
action_result.data.\*.evidence.\*.ipAddress | string | `ip` | 8.8.8.8 |
action_result.data.\*.evidence.\*.loggedOnUsers.\*.accountName | string | | test |
action_result.data.\*.evidence.\*.loggedOnUsers.\*.domainName | string | | TESTMACHINE |
action_result.data.\*.evidence.\*.mdeDeviceId | string | | xxxx84aa7ef0294f733b7b6e9499439e433axxxx |
action_result.data.\*.evidence.\*.onboardingStatus | string | | onboarded |
action_result.data.\*.evidence.\*.osBuild | numeric | | 19044 |
action_result.data.\*.evidence.\*.osPlatform | string | | Windows10 |
action_result.data.\*.evidence.\*.parentProcessCreationDateTime | string | | 2022-03-09T19:52:51Z |
action_result.data.\*.evidence.\*.parentProcessId | numeric | | 7968 |
action_result.data.\*.evidence.\*.parentProcessImageFile | string | | TestFile |
action_result.data.\*.evidence.\*.parentProcessImageFile.fileName | string | | Test.exe |
action_result.data.\*.evidence.\*.parentProcessImageFile.filePath | string | | C:\\Program Files\\Test\\Test\\Application\\Test.exe |
action_result.data.\*.evidence.\*.parentProcessImageFile.filePublisher | string | | Test publisher |
action_result.data.\*.evidence.\*.parentProcessImageFile.fileSize | numeric | | 36557800 |
action_result.data.\*.evidence.\*.parentProcessImageFile.issuer | string | | test issuer |
action_result.data.\*.evidence.\*.parentProcessImageFile.sha1 | string | `sha1` | xxxx9bb316e30ae1a3494ac5b0624f6bea1bxxxx |
action_result.data.\*.evidence.\*.parentProcessImageFile.sha256 | string | `sha256` | xxx14d42706fe215501044acd85a32d58aaef1419d404fddfa5d3b48f66ccxxx |
action_result.data.\*.evidence.\*.parentProcessImageFile.signer | string | | test signer |
action_result.data.\*.evidence.\*.processCommandLine | string | | powershell.exe -ExecutionPolicy AllSigned -NoProfile -NonInteractive |
action_result.data.\*.evidence.\*.processCreationDateTime | string | | 2022-03-09T19:53:01Z |
action_result.data.\*.evidence.\*.processId | numeric | | 6240 |
action_result.data.\*.evidence.\*.rbacGroupId | numeric | | 73 |
action_result.data.\*.evidence.\*.rbacGroupName | string | | UnassignedGroup |
action_result.data.\*.evidence.\*.registryHive | string | | HKEY_LOCAL_MACHINE |
action_result.data.\*.evidence.\*.registryKey | string | | SOFTWARE\\test\\Windows NT\\CurrentVersion\\Image File Execution Options\\Login.scr |
action_result.data.\*.evidence.\*.registryValue | string | | 43-00-3A-00-5C-00-57-00-69-01-6E-10-64-00-6F-00-77-00-73-00-5C-00-53-00-79-00-73-00-74-00-65-00-6D-00-33-00-32-00-5C-00-63-00-61-00-6C-00-63-00-2E-00-65-00-78-00-65-00-00-00 |
action_result.data.\*.evidence.\*.registryValueName | string | | Debugger |
action_result.data.\*.evidence.\*.registryValueType | string | | Unknown |
action_result.data.\*.evidence.\*.remediationStatus | string | | prevented |
action_result.data.\*.evidence.\*.remediationStatusDetails | string | | status details |
action_result.data.\*.evidence.\*.riskScore | string | | high |
action_result.data.\*.evidence.\*.url | string | `url` | test.com |
action_result.data.\*.evidence.\*.userAccount | string | | |
action_result.data.\*.evidence.\*.userAccount.accountName | string | | local service |
action_result.data.\*.evidence.\*.userAccount.azureAdUserId | string | | xxxxxxx |
action_result.data.\*.evidence.\*.userAccount.domainName | string | | nt authority |
action_result.data.\*.evidence.\*.userAccount.userPrincipalName | string | | test |
action_result.data.\*.evidence.\*.userAccount.userSid | string | | S-1-5-19 |
action_result.data.\*.evidence.\*.verdict | string | | unknown |
action_result.data.\*.evidence.\*.version | string | | X1HX |
action_result.data.\*.firstActivityDateTime | string | | 2022-02-23T11:22:20.1835364Z |
action_result.data.\*.id | string | `defender alert id` | xx637812122456454120\_-11082172xx |
action_result.data.\*.incidentId | string | `defender incident id` | 42 |
action_result.data.\*.incidentWebUrl | string | `url` | https://test.com/incidents/42?tid=xxxxc578-c7ee-480d-a225-d48057e7xxxx |
action_result.data.\*.lastActivityDateTime | string | | 2022-02-23T11:22:20.1835364Z |
action_result.data.\*.lastUpdateDateTime | string | | 2022-02-24T03:52:41.7933333Z |
action_result.data.\*.providerAlertId | string | `defender alert id` | xxxx7812122456454120\_-1108217xxx |
action_result.data.\*.recommendedActions | string | | A. Validate the alert and scope the suspected breach.<br>1. Find related machines, network addresses, and files in the incident graph.<br>2. Check for other suspicious activities in the machine timeline.<br>3. Locate unfamiliar processes in the process tree. Check files for prevalence, their locations, and digital signatures.<br>4. Submit relevant files for deep analysis and review file behaviors. <br>5. Identify unusual system activity with system owners. <br><br>B. If you have validated the alert, contain and mitigate the breach.<br>1. Record relevant artifacts, including those you need in mitigation rules.<br>2. Stop suspicious processes. Block prevalent malware files across the network.<br>3. Isolate affected machines.<br>4. Identify potentially compromised accounts. If necessary, reset passwords and decommission accounts.<br>5. Block relevant emails, websites, and IP addresses. Remove attack emails from mailboxes.<br>6. Update antimalware signatures and run full scans. <br>7. Deploy the latest security updates for Windows, web browsers, and other applications.<br><br>C. Contact your incident response team, or contact test support for forensic analysis and remediation services.<br><br>Disclaimer: These guidelines are for reference only. They do not guarantee successful threat removal. |
action_result.data.\*.resolvedDateTime | string | | 2022-02-23T11:24:05.6454411Z |
action_result.data.\*.serviceSource | string | | TestEndpoint |
action_result.data.\*.severity | string | `defender severity` | medium |
action_result.data.\*.status | string | | new |
action_result.data.\*.tenantId | string | | xxxxc578-c7ee-480d-a225-d48057e74df5 |
action_result.data.\*.threatDisplayName | string | | threat |
action_result.data.\*.threatFamilyName | string | | threat |
action_result.data.\*.title | string | | Test alert |
action_result.summary | string | | |
action_result.message | string | | Successfully updated the alert |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |
action_result.data.\*.evidence.\*.hostName | string | | test-id |
action_result.data.\*.evidence.\*.ntDomain | string | | |
action_result.data.\*.evidence.\*.dnsDomain | string | | identity.test |
action_result.data.\*.evidence.\*.@odata.type | string | | #test.graph.security.deviceEvidence |
action_result.data.\*.evidence.\*.lastIpAddress | string | | 10.0.2.15 |
action_result.data.\*.evidence.\*.lastExternalIpAddress | string | | 20.119.52.149 |
action_result.data.\*.evidence.\*.resourceId | string | | /subscriptions/test7906-0000-test-test-1testa8test0/resourceGroups/pluginframework/providers/test.Compute/virtualMachines/test-id |
action_result.data.\*.evidence.\*.resourceName | string | | test-resource |
action_result.data.\*.evidence.\*.resourceType | string | | Virtual Machine |
action_result.data.\*.productName | string | | Test Platform for Cloud |
action_result.data.\*.alertPolicyId | string | | |
action_result.data.\*.@odata.context | string | | https://graph.test.com/v1.0/$metadata#security/alerts_v2/$entity |
action_result.data.\*.additionalData.Intent | numeric | | 8193 |
action_result.data.\*.additionalData.AlertUri | string | | https://test.com/#blade/testa/AlertBlade/alertId/test35test123461_test1230-7777-test-test-testd4test7/subscriptionId/test906-test-dddd-test-test9a8test/resourceGroup/pluginframework/referencedFrom/alertDeepLink/location/centralus |
action_result.data.\*.additionalData.TimeGenerated | string | | 2024-05-16T13:12:23.408Z |
action_result.data.\*.additionalData.Intent@odata.type | string | | #Int64 |
action_result.data.\*.additionalData.ProcessingEndTime | string | | 2024-05-16T13:12:24.022927Z |
action_result.data.\*.additionalData.Attacker source IP | string | | IP Address: 80.94.95.121 |
action_result.data.\*.additionalData.ProductComponentName | string | | Servers |
action_result.data.\*.additionalData.WorkspaceResourceGroup | string | | defaultresourcegroup-eus |
action_result.data.\*.additionalData.Activity end time (UTC) | string | | 2024/05/16 12:45:11.3814938 |
action_result.data.\*.additionalData.EffectiveSubscriptionId | string | | 4c357906-2c22-4d91-98aa-180d9a85a370 |
action_result.data.\*.additionalData.WorkspaceSubscriptionId | string | | 4c357906-2c22-4d91-98aa-180d9a85a370 |
action_result.data.\*.additionalData.EffectiveAzureResourceId | string | | /subscriptions/test7906-2c22-4d91-98aa-180d9a85test/resourceGroups/pluginframework/providers/test.Compute/virtualMachines/test-id |
action_result.data.\*.additionalData.OriginalAlertProductName | string | | Detection-WarmPathV2 |
action_result.data.\*.additionalData.Activity start time (UTC) | string | | 2024/05/16 12:08:57.1962468 |
action_result.data.\*.additionalData.OriginalAlertProviderName | string | | Test Platform for Cloud |
action_result.data.\*.additionalData.Was RDP session initiated | string | | No |
action_result.data.\*.additionalData.Attacker source computer name | string | | Unknown |
action_result.data.\*.additionalData.Number of failed authentication attempts to host | string | | 532 |
action_result.data.\*.additionalData.Top accounts with failed sign in attempts (count) | string | | Zaphod! (1), Gearhostadmin (1), Ssadmin (1), 3 (1), Wheeler (1), Receptionist (1), Jerome (1), Bernie (1), Will (1), 1admin3 (1) |
action_result.data.\*.additionalData.Number of existing accounts used by source to sign in | string | | 1 |
action_result.data.\*.additionalData.Number of nonexistent accounts used by source to sign in | string | | 531 |
action_result.data.\*.Intent_odata_type | string | | #Int64 |

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2025 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
