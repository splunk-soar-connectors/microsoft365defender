[comment]: # "Auto-generated SOAR connector documentation"
# Microsoft 365 Defender

Publisher: Splunk  
Connector Version: 1.1.0  
Product Vendor: Microsoft  
Product Name: Microsoft 365 Defender  
Product Version Supported (regex): ".\*"  
Minimum Product Version: 5.5.0  

This app integrates with Microsoft 365 Defender to execute various generic and investigative actions

[comment]: # " File: README.md"
[comment]: # ""
[comment]: # "Copyright (c) 2022-2023 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License. "
## Port Information

The app uses HTTP/ HTTPS protocol for communicating with the Microsoft 365 Defender server. Below
are the default ports used by Splunk SOAR.

| SERVICE NAME | TRANSPORT PROTOCOL | PORT |
|--------------|--------------------|------|
| http         | tcp                | 80   |
| https        | tcp                | 443  |

## Explanation of Asset Configuration Parameters

-   Tenant ID - It is the Directory ID of the Microsoft Azure Active Directory on the Microsoft
    Azure portal.
-   Client ID - It is the Application ID of an application configured in the Microsoft Azure Active
    Directory.
-   Client Secret - It is the secret string used by the application to prove its identity when
    requesting a token. It can be generated for the configured application on the Microsoft Azure
    Active Directory.
-   Non-Interactive Auth - It is used to determine the authentication method. If it is checked then
    non-Interactive auth will be used otherwise interactive auth will be used. Whenever this
    checkbox is toggled then the test connectivity action must be run again.

## Configure and set up permissions of the app created on the Microsoft Azure portal

<div style="margin-left: 2em">

#### Create the app

1.  Navigate to <https://portal.azure.com> .
2.  Log in with a user that has permission to create an app in the Azure Active Directory (AAD).
3.  Select the 'Azure Active Directory'.
4.  Select the 'App registrations' menu from the left-side panel.
5.  Select the 'New Registration' option at the top of the page.
6.  In the registration form, choose a name for your application and then click 'Register'.

#### Add permissions

7.  Select the 'API Permissions' menu from the left-side panel.
8.  Click on 'Add a permission'.
9.  Under the 'Select an API' section, select 'APIs my organization uses'.
10. Search for 'Microsoft Graph' keyword in the search box and click on the displayed option for it.
11. Provide the following Delegated and Application permissions to the app.
    -   **Application Permissions**

          

        -   SecurityAlert.Read.All
        -   SecurityAlert.ReadWrite.All
        -   ThreatHunting.Read.All
        -   SecurityIncident.Read.All

    -   **Delegated Permissions**

          

        -   SecurityAlert.Read.All
        -   SecurityAlert.ReadWrite.All
        -   ThreatHunting.Read.All
        -   SecurityIncident.Read.All
12. 'Grant Admin Consent' for it.
13. Again click on 'Add a permission'.
14. Under the 'Select an API' section, select 'Microsoft APIs'.
15. Click on the 'Microsoft Graph' option.
16. Provide the following Delegated permission to the app.
    -   **Delegated Permission**

          

        -   offline_access

#### Create a client secret

17. Select the 'Certificates & secrets' menu from the left-side panel.
18. Select 'New client secret' button to open a pop-up window.
19. Provide the description, select an appropriate option for deciding the client secret expiration
    time, and click on the 'Add' button.
20. Click 'Copy to clipboard' to copy the generated secret value and paste it in a safe place. You
    will need it to configure the asset and will not be able to retrieve it later.

#### Copy your application id and tenant id

21. Select the 'Overview' menu from the left-side panel.
22. Copy the **Application (client) ID** and **Directory (tenant) ID** . You will need these to
    configure the SOAR asset.



## Configure the Microsoft 365 Defender SOAR app's asset

When creating an asset for the app,

-   Check the checkbox **Non-Interactive Auth** if you want to use Non-Interactive authentication
    mechanism otherwise Interactive auth mechanism will be used.

-   Provide the client ID of the app created during the previous step of app creation in the 'Client
    ID' field.

-   Provide the client secret of the app created during the previous step of app creation in the
    'Client Secret' field.

-   Provide the tenant ID of the app created during the previous step of Azure app creation in the
    'Tenant ID' field. For getting the value of tenant ID, navigate to the 'Azure Active Directory'
    on the Microsoft Azure portal; click on the 'App registrations' menu from the left-side panel;
    click on the earlier created app. The value displayed in the 'Directory (tenant) ID' is the
    required tenant ID.

-   Save the asset with the above values.

-   After saving the asset, a new uneditable field will appear in the 'Asset Settings' tab of the
    configured asset for the Microsoft 365 Defender app on SOAR. Copy the URL mentioned in the 'POST
    incoming for Microsoft 365 Defender to this location' field. Add a suffix '/result' to the URL
    copied in the previous step. The resulting URL looks like the one mentioned below.

      
      
      

    https://\<soar_host>/rest/handler/microsoft365defender\_\<appid>/\<asset_name>/result

      
      

-   Add the URL created in the earlier step into the 'Redirect URIs' section of the 'Authentication'
    menu for the registered app that was created in the previous steps on the Microsoft Azure
    portal. For the 'Redirect URIs' section, follow the below steps.

      

    1.  Below steps are required only in case of Interactive auth (i.e. If checkbox is unchecked)
    2.  Navigate to the 'Azure Active Directory' on the Microsoft Azure portal.
    3.  Click on the 'App registrations' menu from the left-side panel.
    4.  Click on the earlier created app. You can search for the app by name or client ID.
    5.  Navigate to the 'Authentication' menu of the app on the left-side panel.
    6.  Click on the 'Add a platform' button and select 'Web' from the displayed options.
    7.  Enter the URL created in the earlier section in the 'Redirect URIs' text-box.
    8.  Select the 'ID tokens' checkbox and click 'Save'.
    9.  This will display the 'Redirect URIs' under the 'Web' section displayed on the page.

## Interactive Method to run Test Connectivity

-   Here make sure that the 'Non-Interactive Auth' checkbox is unchecked in asset configuration.
-   After setting up the asset and user, click the 'TEST CONNECTIVITY' button. A pop-up window will
    be displayed with appropriate test connectivity logs. It will also display a specific URL on
    that pop-up window.
-   Open this URL in a separate browser tab. This new tab will redirect to the Microsoft login page
    to complete the login process to grant the permissions to the app.
-   Log in using the same Microsoft account that was used to configure the Microsoft 365 Defender
    workflow and the application on the Microsoft Azure Portal. After logging in, review the
    requested permissions listed and click on the 'Accept' button.
-   This will display a successful message of 'Code received. Please close this window, the action
    will continue to get new token.' on the browser tab.
-   Finally, close the browser tab and come back to the 'Test Connectivity' browser tab. The pop-up
    window should display a 'Test Connectivity Passed' message.

## Non-Interactive Method to run Test Connectivity

-   Here make sure that the 'Non-Interactive Auth' checkbox is checked in asset configuration.
-   Click on the 'TEST CONNECTIVITY' button, it should run the test connectivity action without any
    user interaction.

## Explanation of Test Connectivity Workflow for Interactive auth and Non-Interactive auth

-   This app uses (version 1.0) OAUTH 2.0 authorization code workflow APIs for generating the
    \[access_token\] and \[refresh_token\] pairs if the authentication method is interactive else
    \[access_token\] if authentication method is non-interactive is used for all the API calls to
    the Microsoft 365 Defender instance.

-   Interactive authentication mechanism is a user-context based workflow and the permissions of the
    user also matter along with the API permissions set to define the scope and permissions of the
    generated tokens.

-   Non-Interactive authentication mechanism is a user-context based workflow and the permissions of
    the user also matter along with the API permissions set to define the scope and permissions of
    the generated token.

-   The step-by-step process for the entire authentication mechanism is explained below.

      

    -   The first step is to get an application created in a specific tenant on the Microsoft Azure
        Active Directory. Generate the \[client_secret\] for the configured application. The
        detailed steps have been mentioned in the earlier section.

    -   Configure the Microsoft 365 Defender app's asset with appropriate values for \[tenant_id\],
        \[client_id\], and \[client_secret\] configuration parameters.

    -   Run the test connectivity action for Interactive method.

          

        -   Internally, the connectivity creates a URL for hitting the /authorize endpoint for the
            generation of the authorization code and displays it on the connectivity pop-up window.
            The user is requested to hit this URL in a browser new tab and complete the
            authorization request successfully resulting in the generation of an authorization code.
        -   The authorization code generated in the above step is used by the connectivity to make
            the next API call to generate the \[access_token\] and \[refresh_token\] pair. The
            generated authorization code, \[access_token\], and \[refresh_token\] are stored in the
            state file of the app on the Splunk SOAR server.
        -   The authorization code can be used only once to generate the pair of \[access_token\]
            and \[refresh_token\]. If the \[access_token\] expires, then the \[refresh_token\] is
            used internally automatically by the application to re-generate the \[access_token\] by
            making the corresponding API call. This entire autonomous workflow will seamlessly work
            until the \[refresh_token\] does not get expired. Once the \[refresh_token\] expires,
            the user will have to run the test connectivity action once again to generate the
            authorization code followed by the generation of an entirely fresh pair of
            \[access_token\] and \[refresh_token\]. The default expiration time for the
            \[access_token\] is 1 hour and that of the \[refresh_token\] is 90 days.
        -   The successful run of the Test Connectivity ensures that a valid pair of
            \[access_token\] and \[refresh_token\] has been generated and stored in the app's state
            file. These tokens will be used in all the actions' execution flow to authorize their
            API calls to the Microsoft 365 Defender instance.

    -   Run the test connectivity action for Non-Interactive method.

          

        -   Internally, the application authenticates to Azure AD token issuance endpoint and
            requests an \[access_token\] then it will generate the \[access_token\].
        -   The \[access_token\] generated in the above step is used by the test connectivity to
            make the next API call to verify the \[access_token\]. The generated \[access_token\] is
            stored in the state file of the app on the Splunk SOAR server.
        -   If the \[access_token\] expires, then application will automatically re-generate the
            \[access_token\] by making the corresponding API call.
        -   The successful run of the Test Connectivity ensures that a valid \[access_token\] has
            been generated and stored in the app's state file. This token will be used in all the
            actions execution flow to authorize their API calls to the Microsoft 365 Defender
            instance.

## State file permissions

Please check the permissions for the state file as mentioned below.

#### State file path

-   For Non-NRI instance: /opt/phantom/local_data/app_states/\<appid>/\<asset_id>\_state.json
-   For NRI instance:
    /\<PHANTOM_HOME_DIRECTORY>/local_data/app_states/\<appid>/\<asset_id>\_state.json

#### State file permissions

-   File rights: rw-rw-r-- (664) (The Splunk SOAR user should have read and write access for the
    state file)
-   File owner: Appropriate Splunk SOAR user

## Notes

-   \<appid> - The app ID will be available in the Redirect URI which gets populated in the field
    'POST incoming for Microsoft 365 Defender to this location' when the Microsoft 365 Defender app
    asset is configured e.g.
    https://\<splunk_soar_host>/rest/handler/microsoft365defender\_\<appid>/\<asset_name>/result
-   \<asset_id> - The asset ID will be available on the created asset's Splunk SOAR web URL e.g.
    https://\<splunk_soar_host>/apps/\<app_number>/asset/\<asset_id>/

#### The app is configured and ready to be used now.


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Microsoft 365 Defender asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**tenant_id** |  required  | string | Tenant ID
**client_id** |  required  | string | Client ID
**client_secret** |  required  | password | Client Secret
**non_interactive** |  optional  | boolean | Non-Interactive Auth

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[run query](#action-run-query) - An advanced search query  
[list incidents](#action-list-incidents) - List all the incidents  
[list alerts](#action-list-alerts) - List all the alerts  
[get incident](#action-get-incident) - Retrieve specific incident by its ID  
[get alert](#action-get-alert) - Retrieve specific alert by its ID  
[update alert](#action-update-alert) - Update properties of existing alert  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'run query'
An advanced search query

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**query** |  required  | Query to fetch results | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.query | string |  |   DeviceProcessEvents | limit 5 
action_result.data.\*.DeviceId | string |  |   xxxxx9d48ec4859bd94a25039dcba09f4fd9ac78 
action_result.data.\*.FileName | string |  |   test.exe 
action_result.data.\*.InitiatingProcessFileName | string |  |   powershell.exe 
action_result.data.\*.Timestamp | string |  |   2022-06-12T04:24:25.0406516Z 
action_result.summary.total_results | numeric |  |   1 
action_result.message | string |  |   Total results: 1 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'list incidents'
List all the incidents

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**limit** |  optional  | Maximum number of incidents to return (Defaults to 50) | numeric | 
**offset** |  optional  | Number of incidents to skip (Defaults to 0) | numeric | 
**filter** |  optional  | Filter incidents based on property | string | 
**orderby** |  optional  | Sort the incidents based on property | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.limit | numeric |  |   50 
action_result.parameter.offset | numeric |  |   0 
action_result.parameter.filter | string |  |   status eq 'active' 
action_result.parameter.orderby | string |  |   lastUpdateDateTime desc 
action_result.data.\*.assignedTo | string |  `email`  |   testuser@abc.com 
action_result.data.\*.classification | string |  |   unknown 
action_result.data.\*.comments.\*.comment | string |  |   Testing comment 
action_result.data.\*.comments.\*.createdByDisplayName | string |  |   testuser@abc.com 
action_result.data.\*.comments.\*.createdDateTime | string |  |   2022-06-08T08:34:40.68416Z 
action_result.data.\*.createdDateTime | string |  |   2022-06-13T10:36:05.7Z 
action_result.data.\*.determination | string |  |   unknown 
action_result.data.\*.displayName | string |  |   Malware incident on one endpoint 
action_result.data.\*.id | string |  `defender incident id`  |   145 
action_result.data.\*.incidentWebUrl | string |  `url`  |   https://test.com/incidents/45?tid=xxxxx670-d7ef-580d-a225-d48057e74df6 
action_result.data.\*.lastUpdateDateTime | string |  |   2022-06-13T12:57:22.3633333Z 
action_result.data.\*.redirectIncidentId | string |  `defender incident id`  |   48 
action_result.data.\*.severity | string |  `defender severity`  |   high 
action_result.data.\*.status | string |  |   active 
action_result.data.\*.tenantId | string |  |   xxxxx670-d7ef-580d-a225-d48057e74df6 
action_result.summary.total_incidents | numeric |  |   50 
action_result.message | string |  |   Total incidents: 50 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'list alerts'
List all the alerts

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**limit** |  optional  | Maximum number of alerts to return (Defaults to 2000) | numeric | 
**offset** |  optional  | Number of alerts to skip (Defaults to 0) | numeric | 
**filter** |  optional  | Filter alerts based on property | string | 
**orderby** |  optional  | Sort the alerts based on property | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.limit | numeric |  |   2000 
action_result.parameter.filter | string |  |   status eq 'inProgress' 
action_result.parameter.orderby | string |  |   lastUpdateDateTime desc 
action_result.parameter.offset | numeric |  |   0 
action_result.data.\*.actorDisplayName | string |  |   test@abc.com 
action_result.data.\*.alertWebUrl | string |  `url`  |   https://test.com/alerts/xxxxx812122456454120_-1108217295?tid=a417c578-c7ee-480d-a225-d4805xxxxxxx 
action_result.data.\*.assignedTo | string |  `email`  |   test@abc.com 
action_result.data.\*.category | string |  |   SuspiciousActivity 
action_result.data.\*.classification | string |  |   Test 
action_result.data.\*.comments.\*.comment | string |  |   initialaccess_type_of_alert_last_option from the dropdown 
action_result.data.\*.comments.\*.createdByDisplayName | string |  |   Automation 
action_result.data.\*.comments.\*.createdDateTime | string |  |   2022-04-08T18:03:49.3223829Z 
action_result.data.\*.createdDateTime | string |  |   2022-02-23T11:24:05.6454411Z 
action_result.data.\*.description | string |  |   Test alert 
action_result.data.\*.detectionSource | string |  |   customTi 
action_result.data.\*.detectorId | string |  |   360fdb3b-18a9-471b-9ad0-ad80a4cbcb02 
action_result.data.\*.determination | string |  |   Test 
action_result.data.\*.evidence.\*.@odata.type | string |  |   #test.graph.security.deviceEvidence 
action_result.data.\*.evidence.\*.azureAdDeviceId | string |  |  
action_result.data.\*.evidence.\*.createdDateTime | string |  |   2022-02-23T11:24:05.9366667Z 
action_result.data.\*.evidence.\*.defenderAvStatus | string |  |   unknown 
action_result.data.\*.evidence.\*.detectionStatus | string |  |   Test 
action_result.data.\*.evidence.\*.deviceDnsName | string |  |   testmachine 
action_result.data.\*.evidence.\*.fileDetails.fileName | string |  |   C:\\Program Files\\Test\\Test\\Application\\Test.exe 
action_result.data.\*.evidence.\*.fileDetails.filePath | string |  |   C:\\Program Files\\Test\\Test\\Application 
action_result.data.\*.evidence.\*.fileDetails.filePublisher | string |  |   Test 
action_result.data.\*.evidence.\*.fileDetails.fileSize | numeric |  |   77312 
action_result.data.\*.evidence.\*.fileDetails.issuer | string |  |   file issuer 
action_result.data.\*.evidence.\*.fileDetails.sha1 | string |  `sha1`  |   xxx8825f6b54238a452e3050d49e8aa50569a6c9 
action_result.data.\*.evidence.\*.fileDetails.sha256 | string |  `sha256`  |   xxxx4eecd1b9d02a7d6b6d8c9e9c82cc5ce16bfa7c2932944d0bf0fbb13fxxxx 
action_result.data.\*.evidence.\*.fileDetails.signer | string |  |   signer 
action_result.data.\*.evidence.\*.firstSeenDateTime | string |  |   2021-08-30T16:25:37.180194Z 
action_result.data.\*.evidence.\*.healthStatus | string |  |   inactive 
action_result.data.\*.evidence.\*.imageFile.fileName | string |  |   powershell.exe 
action_result.data.\*.evidence.\*.imageFile.filePath | string |  |   c:\\windows\\system32\\windowspowershell\\v1.0 
action_result.data.\*.evidence.\*.imageFile.filePublisher | string |  |   test publisher 
action_result.data.\*.evidence.\*.imageFile.fileSize | numeric |  |   99912 
action_result.data.\*.evidence.\*.imageFile.issuer | string |  |   test issuer 
action_result.data.\*.evidence.\*.imageFile.sha1 | string |  `sha1`  |   xxxx9bb316e30ae1a3494ac5b0624f6bea1bxxxx 
action_result.data.\*.evidence.\*.imageFile.sha256 | string |  `sha256`  |   xxx14d42706fe215501044acd85a32d58aaef1419d404fddfa5d3b48f66ccxxx 
action_result.data.\*.evidence.\*.imageFile.signer | string |  |   test signer 
action_result.data.\*.evidence.\*.ipAddress | string |  `ip`  |   8.8.8.8 
action_result.data.\*.evidence.\*.loggedOnUsers.\*.accountName | string |  |   test 
action_result.data.\*.evidence.\*.loggedOnUsers.\*.domainName | string |  |   TESTMACHINE 
action_result.data.\*.evidence.\*.mdeDeviceId | string |  |   xxxx84aa7ef0294f733b7b6e9499439e433axxxx 
action_result.data.\*.evidence.\*.onboardingStatus | string |  |   onboarded 
action_result.data.\*.evidence.\*.osBuild | numeric |  |   19044 
action_result.data.\*.evidence.\*.osPlatform | string |  |   Windows10 
action_result.data.\*.evidence.\*.parentProcessCreationDateTime | string |  |   2022-03-09T19:52:51Z 
action_result.data.\*.evidence.\*.parentProcessId | numeric |  |   7968 
action_result.data.\*.evidence.\*.parentProcessImageFile | string |  |   TestFile 
action_result.data.\*.evidence.\*.parentProcessImageFile.fileName | string |  |   Test.exe 
action_result.data.\*.evidence.\*.parentProcessImageFile.filePath | string |  |   C:\\Program Files\\Test\\Test\\Application\\Test.exe 
action_result.data.\*.evidence.\*.parentProcessImageFile.filePublisher | string |  |   Test publisher 
action_result.data.\*.evidence.\*.parentProcessImageFile.fileSize | numeric |  |   36557800 
action_result.data.\*.evidence.\*.parentProcessImageFile.issuer | string |  |   test issuer 
action_result.data.\*.evidence.\*.parentProcessImageFile.sha1 | string |  `sha1`  |   xxxx9bb316e30ae1a3494ac5b0624f6bea1bxxxx 
action_result.data.\*.evidence.\*.parentProcessImageFile.sha256 | string |  `sha256`  |   xxx14d42706fe215501044acd85a32d58aaef1419d404fddfa5d3b48f66ccxxx 
action_result.data.\*.evidence.\*.parentProcessImageFile.signer | string |  |   test signer 
action_result.data.\*.evidence.\*.processCommandLine | string |  |   powershell.exe -ExecutionPolicy AllSigned -NoProfile -NonInteractive 
action_result.data.\*.evidence.\*.processCreationDateTime | string |  |   2022-03-09T19:53:01Z 
action_result.data.\*.evidence.\*.processId | numeric |  |   6240 
action_result.data.\*.evidence.\*.rbacGroupId | numeric |  |   73 
action_result.data.\*.evidence.\*.rbacGroupName | string |  |   UnassignedGroup 
action_result.data.\*.evidence.\*.registryHive | string |  |   HKEY_LOCAL_MACHINE 
action_result.data.\*.evidence.\*.registryKey | string |  |   SOFTWARE\\test\\Windows NT\\CurrentVersion\\Image File Execution Options\\Login.scr 
action_result.data.\*.evidence.\*.registryValue | string |  |   43-00-3A-00-5C-00-57-00-69-01-6E-10-64-00-6F-00-77-00-73-00-5C-00-53-00-79-00-73-00-74-00-65-00-6D-00-33-00-32-00-5C-00-63-00-61-00-6C-00-63-00-2E-00-65-00-78-00-65-00-00-00 
action_result.data.\*.evidence.\*.registryValueName | string |  |   Debugger 
action_result.data.\*.evidence.\*.registryValueType | string |  |   Unknown 
action_result.data.\*.evidence.\*.remediationStatus | string |  |   prevented 
action_result.data.\*.evidence.\*.remediationStatusDetails | string |  |   status details 
action_result.data.\*.evidence.\*.riskScore | string |  |   high 
action_result.data.\*.evidence.\*.url | string |  `url`  |   test.com 
action_result.data.\*.evidence.\*.userAccount | string |  |  
action_result.data.\*.evidence.\*.userAccount.accountName | string |  |   local service 
action_result.data.\*.evidence.\*.userAccount.azureAdUserId | string |  |   xxxxxxx 
action_result.data.\*.evidence.\*.userAccount.domainName | string |  |   nt authority 
action_result.data.\*.evidence.\*.userAccount.userPrincipalName | string |  |   test 
action_result.data.\*.evidence.\*.userAccount.userSid | string |  |   S-1-5-19 
action_result.data.\*.evidence.\*.verdict | string |  |   unknown 
action_result.data.\*.evidence.\*.version | string |  |   X1HX 
action_result.data.\*.firstActivityDateTime | string |  |   2022-02-23T11:22:20.1835364Z 
action_result.data.\*.id | string |  `defender alert id`  |   xx637812122456454120_-11082172xx 
action_result.data.\*.incidentId | string |  `defender incident id`  |   42 
action_result.data.\*.incidentWebUrl | string |  `url`  |   https://test.com/incidents/42?tid=xxxxc578-c7ee-480d-a225-d48057e7xxxx 
action_result.data.\*.lastActivityDateTime | string |  |   2022-02-23T11:22:20.1835364Z 
action_result.data.\*.lastUpdateDateTime | string |  |   2022-02-24T03:52:41.7933333Z 
action_result.data.\*.providerAlertId | string |  `defender alert id`  |   xxxx7812122456454120_-1108217xxx 
action_result.data.\*.recommendedActions | string |  |   A. Validate the alert and scope the suspected breach.
1. Find related machines, network addresses, and files in the incident graph.
2. Check for other suspicious activities in the machine timeline.
3. Locate unfamiliar processes in the process tree. Check files for prevalence, their locations, and digital signatures.
4. Submit relevant files for deep analysis and review file behaviors. 
5. Identify unusual system activity with system owners. 

B. If you have validated the alert, contain and mitigate the breach.
1. Record relevant artifacts, including those you need in mitigation rules.
2. Stop suspicious processes. Block prevalent malware files across the network.
3. Isolate affected machines.
4. Identify potentially compromised accounts. If necessary, reset passwords and decommission accounts.
5. Block relevant emails, websites, and IP addresses. Remove attack emails from mailboxes.
6. Update antimalware signatures and run full scans. 
7. Deploy the latest security updates for Windows, web browsers, and other applications.

C. Contact your incident response team, or contact test support for forensic analysis and remediation services.

Disclaimer: These guidelines are for reference only. They do not guarantee successful threat removal. 
action_result.data.\*.resolvedDateTime | string |  |   2022-02-23T11:24:05.6454411Z 
action_result.data.\*.serviceSource | string |  |   TestEndpoint 
action_result.data.\*.severity | string |  `defender severity`  |   medium 
action_result.data.\*.status | string |  |   new 
action_result.data.\*.tenantId | string |  |   xxxxc578-c7ee-480d-a225-d48057e74df5 
action_result.data.\*.threatDisplayName | string |  |   threat 
action_result.data.\*.threatFamilyName | string |  |   threat 
action_result.data.\*.title | string |  |   Test alert 
action_result.summary.total_alerts | numeric |  |   2 
action_result.message | string |  |   Total alerts: 2 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'get incident'
Retrieve specific incident by its ID

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**incident_id** |  required  | ID of the incident | string |  `defender incident id` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.incident_id | string |  `defender incident id`  |   48 
action_result.data.\*.assignedTo | string |  `email`  |   testuser@abc.com 
action_result.data.\*.classification | string |  |   unknown 
action_result.data.\*.comments.\*.comment | string |  |  
action_result.data.\*.comments.\*.createdByDisplayName | string |  |   testuser@abc.com 
action_result.data.\*.comments.\*.createdDateTime | string |  |   2022-06-08T08:34:40.68416Z 
action_result.data.\*.createdDateTime | string |  |   2022-06-13T10:36:05.7Z 
action_result.data.\*.determination | string |  |   unknown 
action_result.data.\*.displayName | string |  |   Test alert on one endpoint 
action_result.data.\*.id | string |  `defender incident id`  |   145 
action_result.data.\*.incidentWebUrl | string |  `url`  |   https://test.com/incidents/45?tid=xxxxx670-d7ef-580d-a225-d48057e74df6 
action_result.data.\*.lastUpdateDateTime | string |  |   2022-06-13T12:57:22.3633333Z 
action_result.data.\*.redirectIncidentId | string |  `defender incident id`  |   48 
action_result.data.\*.severity | string |  `defender severity`  |   high 
action_result.data.\*.status | string |  |   active 
action_result.data.\*.tags.\* | string |  |  
action_result.data.\*.tenantId | string |  `microsoft tenantid`  |   xxxxx670-d7ef-580d-a225-d48057e74df6 
action_result.summary | string |  |  
action_result.message | string |  |   Successfully retrieved the incident 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'get alert'
Retrieve specific alert by its ID

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**alert_id** |  required  | ID of the alert | string |  `defender alert id` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.alert_id | string |  `defender alert id`  |   xxxxx812122456454120_-11082xxxxx 
action_result.data.\*.actorDisplayName | string |  |   test@abc.com 
action_result.data.\*.alertWebUrl | string |  |   https://test.com/alerts/xxxxx812122456454120_-1108217295?tid=a417c578-c7ee-480d-a225-d4805xxxxxxx 
action_result.data.\*.assignedTo | string |  `email`  |   test@abc.com 
action_result.data.\*.category | string |  |   SuspiciousActivity 
action_result.data.\*.classification | string |  |   Test 
action_result.data.\*.comments.\*.comment | string |  |   initialaccess_type_of_alert_last_option from the dropdown 
action_result.data.\*.comments.\*.createdByDisplayName | string |  |   Automation 
action_result.data.\*.comments.\*.createdDateTime | string |  |   2022-04-08T18:03:49.3223829Z 
action_result.data.\*.createdDateTime | string |  |   2022-02-23T11:24:05.6454411Z 
action_result.data.\*.description | string |  |   Test alert 
action_result.data.\*.detectionSource | string |  |   customTi 
action_result.data.\*.detectorId | string |  |   360fdb3b-18a9-471b-9ad0-ad80a4cbcb02 
action_result.data.\*.determination | string |  |   Test 
action_result.data.\*.evidence.\*.@odata.type | string |  |   #test.graph.security.deviceEvidence 
action_result.data.\*.evidence.\*.azureAdDeviceId | string |  |  
action_result.data.\*.evidence.\*.createdDateTime | string |  |   2022-02-23T11:24:05.9366667Z 
action_result.data.\*.evidence.\*.defenderAvStatus | string |  |   unknown 
action_result.data.\*.evidence.\*.detectionStatus | string |  |   Test 
action_result.data.\*.evidence.\*.deviceDnsName | string |  |   testmachine 
action_result.data.\*.evidence.\*.fileDetails.fileName | string |  |   C:\\Program Files\\Test\\Test\\Application\\Test.exe 
action_result.data.\*.evidence.\*.fileDetails.filePath | string |  |   C:\\Program Files\\Test\\Test\\Application 
action_result.data.\*.evidence.\*.fileDetails.filePublisher | string |  |   Test 
action_result.data.\*.evidence.\*.fileDetails.fileSize | numeric |  |   77312 
action_result.data.\*.evidence.\*.fileDetails.issuer | string |  |   file issuer 
action_result.data.\*.evidence.\*.fileDetails.sha1 | string |  `sha1`  |   xxx8825f6b54238a452e3050d49e8aa50569a6c9 
action_result.data.\*.evidence.\*.fileDetails.sha256 | string |  `sha256`  |   7db34eecd1b9d02a7d6b6d8c9e9c82cc5ce16bfa7c2932944d0bf0fbb13f5bc6 
action_result.data.\*.evidence.\*.fileDetails.signer | string |  |   signer 
action_result.data.\*.evidence.\*.firstSeenDateTime | string |  |   2021-08-30T16:25:37.180194Z 
action_result.data.\*.evidence.\*.healthStatus | string |  |   inactive 
action_result.data.\*.evidence.\*.imageFile.fileName | string |  |   powershell.exe 
action_result.data.\*.evidence.\*.imageFile.filePath | string |  |   c:\\windows\\system32\\windowspowershell\\v1.0 
action_result.data.\*.evidence.\*.imageFile.filePublisher | string |  |   test publisher 
action_result.data.\*.evidence.\*.imageFile.fileSize | numeric |  |   99912 
action_result.data.\*.evidence.\*.imageFile.issuer | string |  |   test issuer 
action_result.data.\*.evidence.\*.imageFile.sha1 | string |  `sha1`  |   xxxx9bb316e30ae1a3494ac5b0624f6bea1bxxxx 
action_result.data.\*.evidence.\*.imageFile.sha256 | string |  `sha256`  |   xxx14d42706fe215501044acd85a32d58aaef1419d404fddfa5d3b48f66ccxxx 
action_result.data.\*.evidence.\*.imageFile.signer | string |  |   test signer 
action_result.data.\*.evidence.\*.ipAddress | string |  `ip`  |   8.8.8.8 
action_result.data.\*.evidence.\*.loggedOnUsers.\*.accountName | string |  |   test 
action_result.data.\*.evidence.\*.loggedOnUsers.\*.domainName | string |  |   TESTMACHINE 
action_result.data.\*.evidence.\*.mdeDeviceId | string |  |   xxxx84aa7ef0294f733b7b6e9499439e433axxxx 
action_result.data.\*.evidence.\*.onboardingStatus | string |  |   onboarded 
action_result.data.\*.evidence.\*.osBuild | numeric |  |   19044 
action_result.data.\*.evidence.\*.osPlatform | string |  |   Windows10 
action_result.data.\*.evidence.\*.parentProcessCreationDateTime | string |  |   2022-03-09T19:52:51Z 
action_result.data.\*.evidence.\*.parentProcessId | numeric |  |   7968 
action_result.data.\*.evidence.\*.parentProcessImageFile | string |  |   TestFile 
action_result.data.\*.evidence.\*.parentProcessImageFile.fileName | string |  |   Test.exe 
action_result.data.\*.evidence.\*.parentProcessImageFile.filePath | string |  |   C:\\Program Files\\Test\\Test\\Application\\Test.exe 
action_result.data.\*.evidence.\*.parentProcessImageFile.filePublisher | string |  |   Test publisher 
action_result.data.\*.evidence.\*.parentProcessImageFile.fileSize | numeric |  |   36557800 
action_result.data.\*.evidence.\*.parentProcessImageFile.issuer | string |  |   test issuer 
action_result.data.\*.evidence.\*.parentProcessImageFile.sha1 | string |  `sha1`  |   xxxx9bb316e30ae1a3494ac5b0624f6bea1bxxxx 
action_result.data.\*.evidence.\*.parentProcessImageFile.sha256 | string |  `sha256`  |   xxx14d42706fe215501044acd85a32d58aaef1419d404fddfa5d3b48f66ccxxx 
action_result.data.\*.evidence.\*.parentProcessImageFile.signer | string |  |   test signer 
action_result.data.\*.evidence.\*.processCommandLine | string |  |   powershell.exe -ExecutionPolicy AllSigned -NoProfile -NonInteractive 
action_result.data.\*.evidence.\*.processCreationDateTime | string |  |   2022-03-09T19:53:01Z 
action_result.data.\*.evidence.\*.processId | numeric |  |   6240 
action_result.data.\*.evidence.\*.rbacGroupId | numeric |  |   73 
action_result.data.\*.evidence.\*.rbacGroupName | string |  |   UnassignedGroup 
action_result.data.\*.evidence.\*.registryHive | string |  |   HKEY_LOCAL_MACHINE 
action_result.data.\*.evidence.\*.registryKey | string |  |   SOFTWARE\\test\\Windows NT\\CurrentVersion\\Image File Execution Options\\Login.scr 
action_result.data.\*.evidence.\*.registryValue | string |  |   43-00-3A-00-5C-00-57-00-69-01-6E-10-64-00-6F-00-77-00-73-00-5C-00-53-00-79-00-73-00-74-00-65-00-6D-00-33-00-32-00-5C-00-63-00-61-00-6C-00-63-00-2E-00-65-00-78-00-65-00-00-00 
action_result.data.\*.evidence.\*.registryValueName | string |  |   Debugger 
action_result.data.\*.evidence.\*.registryValueType | string |  |   Unknown 
action_result.data.\*.evidence.\*.remediationStatus | string |  |   prevented 
action_result.data.\*.evidence.\*.remediationStatusDetails | string |  |   status details 
action_result.data.\*.evidence.\*.riskScore | string |  |   high 
action_result.data.\*.evidence.\*.url | string |  `url`  |   test.com 
action_result.data.\*.evidence.\*.userAccount | string |  |  
action_result.data.\*.evidence.\*.userAccount.accountName | string |  |   local service 
action_result.data.\*.evidence.\*.userAccount.azureAdUserId | string |  |   xxxxxxx 
action_result.data.\*.evidence.\*.userAccount.domainName | string |  |   nt authority 
action_result.data.\*.evidence.\*.userAccount.userPrincipalName | string |  |   test 
action_result.data.\*.evidence.\*.userAccount.userSid | string |  |   S-1-5-19 
action_result.data.\*.evidence.\*.verdict | string |  |   unknown 
action_result.data.\*.evidence.\*.version | string |  |   X1HX 
action_result.data.\*.firstActivityDateTime | string |  |   2022-02-23T11:22:20.1835364Z 
action_result.data.\*.id | string |  `defender alert id`  |   xx637812122456454120_-11082172xx 
action_result.data.\*.incidentId | string |  `defender incident id`  |   42 
action_result.data.\*.incidentWebUrl | string |  `url`  |   https://test.com/incidents/42?tid=xxxxc578-c7ee-480d-a225-d48057e7xxxx 
action_result.data.\*.lastActivityDateTime | string |  |   2022-02-23T11:22:20.1835364Z 
action_result.data.\*.lastUpdateDateTime | string |  |   2022-02-24T03:52:41.7933333Z 
action_result.data.\*.providerAlertId | string |  `defender alert id`  |   xxxx7812122456454120_-1108217xxx 
action_result.data.\*.recommendedActions | string |  |   A. Validate the alert and scope the suspected breach.
1. Find related machines, network addresses, and files in the incident graph.
2. Check for other suspicious activities in the machine timeline.
3. Locate unfamiliar processes in the process tree. Check files for prevalence, their locations, and digital signatures.
4. Submit relevant files for deep analysis and review file behaviors. 
5. Identify unusual system activity with system owners. 

B. If you have validated the alert, contain and mitigate the breach.
1. Record relevant artifacts, including those you need in mitigation rules.
2. Stop suspicious processes. Block prevalent malware files across the network.
3. Isolate affected machines.
4. Identify potentially compromised accounts. If necessary, reset passwords and decommission accounts.
5. Block relevant emails, websites, and IP addresses. Remove attack emails from mailboxes.
6. Update antimalware signatures and run full scans. 
7. Deploy the latest security updates for Windows, web browsers, and other applications.

C. Contact your incident response team, or contact test support for forensic analysis and remediation services.

Disclaimer: These guidelines are for reference only. They do not guarantee successful threat removal. 
action_result.data.\*.resolvedDateTime | string |  |   2022-02-23T11:24:05.6454411Z 
action_result.data.\*.serviceSource | string |  |   TestEndpoint 
action_result.data.\*.severity | string |  `defender severity`  |   medium 
action_result.data.\*.status | string |  |   new 
action_result.data.\*.tenantId | string |  |   xxxxc578-c7ee-480d-a225-d48057e74df5 
action_result.data.\*.threatDisplayName | string |  |   threat 
action_result.data.\*.threatFamilyName | string |  |   threat 
action_result.data.\*.title | string |  |   Test alert 
action_result.summary | string |  |  
action_result.message | string |  |   Successfully retrieved the alert 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'update alert'
Update properties of existing alert

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**alert_id** |  required  | ID of the alert | string |  `defender alert id` 
**status** |  optional  | Specifies the status of the alert | string | 
**assign_to** |  optional  | Owner of the alert | string |  `email` 
**classification** |  optional  | Specifies the specification of the alert | string | 
**determination** |  optional  | Specifies the determination of the alert | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.alert_id | string |  `defender alert id`  |   xx637812122456454120_-11082172xx 
action_result.parameter.assign_to | string |  `email`  |   test@abc.com 
action_result.parameter.classification | string |  |   Unknown 
action_result.parameter.determination | string |  |   Other 
action_result.parameter.status | string |  |   New 
action_result.data.\*.@odata.context | string |  `url`  |   https://graph.microsoft.com/beta/$metadata#security/alerts_v2/$entity 
action_result.data.\*.mitreTechniques.\* | string |  |   T1546.008 
action_result.data.\*.evidence.\*.tags.\* | string |  |   testtag 
action_result.data.\*.evidence.\*.vmMetadata.vmId | string |  |  
action_result.data.\*.evidence.\*.vmMetadata.resourceId | string |  |  
action_result.data.\*.evidence.\*.vmMetadata.cloudProvider | string |  |  
action_result.data.\*.evidence.\*.vmMetadata.subscriptionId | string |  |  
action_result.data.\*.actorDisplayName | string |  |   test@abc.com 
action_result.data.\*.alertWebUrl | string |  `url`  |   https://test.com/alerts/xxxxx812122456454120_-1108217295?tid=a417c578-c7ee-480d-a225-d4805xxxxxxx 
action_result.data.\*.assignedTo | string |  `email`  |   test@abc.com 
action_result.data.\*.category | string |  |   SuspiciousActivity 
action_result.data.\*.classification | string |  |   Test 
action_result.data.\*.comments.\*.comment | string |  |   initialaccess_type_of_alert_last_option from the dropdown 
action_result.data.\*.comments.\*.createdByDisplayName | string |  |   Automation 
action_result.data.\*.comments.\*.createdDateTime | string |  |   2022-04-08T18:03:49.3223829Z 
action_result.data.\*.createdDateTime | string |  |   2022-02-23T11:24:05.6454411Z 
action_result.data.\*.description | string |  |   Test alert 
action_result.data.\*.detectionSource | string |  |   customTi 
action_result.data.\*.detectorId | string |  |   360fdb3b-18a9-471b-9ad0-ad80a4cbcb02 
action_result.data.\*.determination | string |  |   Test 
action_result.data.\*.evidence.\*.@odata.type | string |  |   #test.graph.security.deviceEvidence 
action_result.data.\*.evidence.\*.azureAdDeviceId | string |  |  
action_result.data.\*.evidence.\*.createdDateTime | string |  |   2022-02-23T11:24:05.9366667Z 
action_result.data.\*.evidence.\*.defenderAvStatus | string |  |   unknown 
action_result.data.\*.evidence.\*.detectionStatus | string |  |   Test 
action_result.data.\*.evidence.\*.deviceDnsName | string |  |   testmachine 
action_result.data.\*.evidence.\*.fileDetails.fileName | string |  |   C:\\Program Files\\Test\\Test\\Application\\Test.exe 
action_result.data.\*.evidence.\*.fileDetails.filePath | string |  |   C:\\Program Files\\Test\\Test\\Application 
action_result.data.\*.evidence.\*.fileDetails.filePublisher | string |  |   Test 
action_result.data.\*.evidence.\*.fileDetails.fileSize | numeric |  |   77312 
action_result.data.\*.evidence.\*.fileDetails.issuer | string |  |   file issuer 
action_result.data.\*.evidence.\*.fileDetails.sha1 | string |  `sha1`  |   xxx8825f6b54238a452e3050d49e8aa50569a6c9 
action_result.data.\*.evidence.\*.fileDetails.sha256 | string |  `sha256`  |   7db34eecd1b9d02a7d6b6d8c9e9c82cc5ce16bfa7c2932944d0bf0fbb13f5bc6 
action_result.data.\*.evidence.\*.fileDetails.signer | string |  |   signer 
action_result.data.\*.evidence.\*.firstSeenDateTime | string |  |   2021-08-30T16:25:37.180194Z 
action_result.data.\*.evidence.\*.healthStatus | string |  |   inactive 
action_result.data.\*.evidence.\*.imageFile.fileName | string |  |   powershell.exe 
action_result.data.\*.evidence.\*.imageFile.filePath | string |  |   c:\\windows\\system32\\windowspowershell\\v1.0 
action_result.data.\*.evidence.\*.imageFile.filePublisher | string |  |   test publisher 
action_result.data.\*.evidence.\*.imageFile.fileSize | numeric |  |   99912 
action_result.data.\*.evidence.\*.imageFile.issuer | string |  |   test issuer 
action_result.data.\*.evidence.\*.imageFile.sha1 | string |  `sha1`  |   xxxx9bb316e30ae1a3494ac5b0624f6bea1bxxxx 
action_result.data.\*.evidence.\*.imageFile.sha256 | string |  `sha256`  |   xxx14d42706fe215501044acd85a32d58aaef1419d404fddfa5d3b48f66ccxxx 
action_result.data.\*.evidence.\*.imageFile.signer | string |  |   test signer 
action_result.data.\*.evidence.\*.ipAddress | string |  `ip`  |   8.8.8.8 
action_result.data.\*.evidence.\*.loggedOnUsers.\*.accountName | string |  |   test 
action_result.data.\*.evidence.\*.loggedOnUsers.\*.domainName | string |  |   TESTMACHINE 
action_result.data.\*.evidence.\*.mdeDeviceId | string |  |   xxxx84aa7ef0294f733b7b6e9499439e433axxxx 
action_result.data.\*.evidence.\*.onboardingStatus | string |  |   onboarded 
action_result.data.\*.evidence.\*.osBuild | numeric |  |   19044 
action_result.data.\*.evidence.\*.osPlatform | string |  |   Windows10 
action_result.data.\*.evidence.\*.parentProcessCreationDateTime | string |  |   2022-03-09T19:52:51Z 
action_result.data.\*.evidence.\*.parentProcessId | numeric |  |   7968 
action_result.data.\*.evidence.\*.parentProcessImageFile | string |  |   TestFile 
action_result.data.\*.evidence.\*.parentProcessImageFile.fileName | string |  |   Test.exe 
action_result.data.\*.evidence.\*.parentProcessImageFile.filePath | string |  |   C:\\Program Files\\Test\\Test\\Application\\Test.exe 
action_result.data.\*.evidence.\*.parentProcessImageFile.filePublisher | string |  |   Test publisher 
action_result.data.\*.evidence.\*.parentProcessImageFile.fileSize | numeric |  |   36557800 
action_result.data.\*.evidence.\*.parentProcessImageFile.issuer | string |  |   test issuer 
action_result.data.\*.evidence.\*.parentProcessImageFile.sha1 | string |  `sha1`  |   xxxx9bb316e30ae1a3494ac5b0624f6bea1bxxxx 
action_result.data.\*.evidence.\*.parentProcessImageFile.sha256 | string |  `sha256`  |   xxx14d42706fe215501044acd85a32d58aaef1419d404fddfa5d3b48f66ccxxx 
action_result.data.\*.evidence.\*.parentProcessImageFile.signer | string |  |   test signer 
action_result.data.\*.evidence.\*.processCommandLine | string |  |   powershell.exe -ExecutionPolicy AllSigned -NoProfile -NonInteractive 
action_result.data.\*.evidence.\*.processCreationDateTime | string |  |   2022-03-09T19:53:01Z 
action_result.data.\*.evidence.\*.processId | numeric |  |   6240 
action_result.data.\*.evidence.\*.rbacGroupId | numeric |  |   73 
action_result.data.\*.evidence.\*.rbacGroupName | string |  |   UnassignedGroup 
action_result.data.\*.evidence.\*.registryHive | string |  |   HKEY_LOCAL_MACHINE 
action_result.data.\*.evidence.\*.registryKey | string |  |   SOFTWARE\\test\\Windows NT\\CurrentVersion\\Image File Execution Options\\Login.scr 
action_result.data.\*.evidence.\*.registryValue | string |  |   43-00-3A-00-5C-00-57-00-69-01-6E-10-64-00-6F-00-77-00-73-00-5C-00-53-00-79-00-73-00-74-00-65-00-6D-00-33-00-32-00-5C-00-63-00-61-00-6C-00-63-00-2E-00-65-00-78-00-65-00-00-00 
action_result.data.\*.evidence.\*.registryValueName | string |  |   Debugger 
action_result.data.\*.evidence.\*.registryValueType | string |  |   Unknown 
action_result.data.\*.evidence.\*.remediationStatus | string |  |   prevented 
action_result.data.\*.evidence.\*.remediationStatusDetails | string |  |   status details 
action_result.data.\*.evidence.\*.riskScore | string |  |   high 
action_result.data.\*.evidence.\*.url | string |  `url`  |   test.com 
action_result.data.\*.evidence.\*.userAccount | string |  |  
action_result.data.\*.evidence.\*.userAccount.accountName | string |  |   local service 
action_result.data.\*.evidence.\*.userAccount.azureAdUserId | string |  |   xxxxxxx 
action_result.data.\*.evidence.\*.userAccount.domainName | string |  |   nt authority 
action_result.data.\*.evidence.\*.userAccount.userPrincipalName | string |  |   test 
action_result.data.\*.evidence.\*.userAccount.userSid | string |  |   S-1-5-19 
action_result.data.\*.evidence.\*.verdict | string |  |   unknown 
action_result.data.\*.evidence.\*.version | string |  |   X1HX 
action_result.data.\*.firstActivityDateTime | string |  |   2022-02-23T11:22:20.1835364Z 
action_result.data.\*.id | string |  `defender alert id`  |   xx637812122456454120_-11082172xx 
action_result.data.\*.incidentId | string |  `defender incident id`  |   42 
action_result.data.\*.incidentWebUrl | string |  `url`  |   https://test.com/incidents/42?tid=xxxxc578-c7ee-480d-a225-d48057e7xxxx 
action_result.data.\*.lastActivityDateTime | string |  |   2022-02-23T11:22:20.1835364Z 
action_result.data.\*.lastUpdateDateTime | string |  |   2022-02-24T03:52:41.7933333Z 
action_result.data.\*.providerAlertId | string |  `defender alert id`  |   xxxx7812122456454120_-1108217xxx 
action_result.data.\*.recommendedActions | string |  |   A. Validate the alert and scope the suspected breach.
1. Find related machines, network addresses, and files in the incident graph.
2. Check for other suspicious activities in the machine timeline.
3. Locate unfamiliar processes in the process tree. Check files for prevalence, their locations, and digital signatures.
4. Submit relevant files for deep analysis and review file behaviors. 
5. Identify unusual system activity with system owners. 

B. If you have validated the alert, contain and mitigate the breach.
1. Record relevant artifacts, including those you need in mitigation rules.
2. Stop suspicious processes. Block prevalent malware files across the network.
3. Isolate affected machines.
4. Identify potentially compromised accounts. If necessary, reset passwords and decommission accounts.
5. Block relevant emails, websites, and IP addresses. Remove attack emails from mailboxes.
6. Update antimalware signatures and run full scans. 
7. Deploy the latest security updates for Windows, web browsers, and other applications.

C. Contact your incident response team, or contact test support for forensic analysis and remediation services.

Disclaimer: These guidelines are for reference only. They do not guarantee successful threat removal. 
action_result.data.\*.resolvedDateTime | string |  |   2022-02-23T11:24:05.6454411Z 
action_result.data.\*.serviceSource | string |  |   TestEndpoint 
action_result.data.\*.severity | string |  `defender severity`  |   medium 
action_result.data.\*.status | string |  |   new 
action_result.data.\*.tenantId | string |  |   xxxxc578-c7ee-480d-a225-d48057e74df5 
action_result.data.\*.threatDisplayName | string |  |   threat 
action_result.data.\*.threatFamilyName | string |  |   threat 
action_result.data.\*.title | string |  |   Test alert 
action_result.summary | string |  |  
action_result.message | string |  |   Successfully updated the alert 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1 