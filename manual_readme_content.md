[comment]: # " File: README.md"
[comment]: # ""
[comment]: # "Copyright (c) 2022-2024 Splunk Inc."
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

-   Tenant ID - It is the Directory ID of the Microsoft Entra ID on the Microsoft
    Azure portal.
-   Client ID - It is the Application ID of an application configured in the Microsoft Entra ID.
-   Client Secret - It is the secret string used by the application to prove its identity when
    requesting a token. It can be generated for the configured application on the Microsoft Entra ID.
-   Non-Interactive Auth - It is used to determine the authentication method. If it is checked then
    non-Interactive auth will be used otherwise interactive auth will be used. Whenever this
    checkbox is toggled then the test connectivity action must be run again.
-   Timeout - It is used to make configurable timeout for all actions.

## Explanation of Asset Configuration Parameters for On Poll

-   Max Incidents For Polling - In each polling cycle, incidents are fetched for schedule and interval polling based on the provided value (Default 1000). Containers are created per incident.
-   Start Time - It is used to filter the incidents based on start time, if nothing is provided, then it will take last week as start time. <br> **NOTE: Start time is used to filter based on lastUpdateDateTime property of incident**
-   Filter - It is used to add extra filters on incident properties.

## Explanation of On Poll Behavior

-    The default incident order is set to "lastUpdateDateTime," prioritizing the latest incidents as newest.
-    The start time parameter value aligns with the lastUpdateDateTime of the incident. 
-    The maximum incidents parameter functions exclusively with scheduled and interval polling.
-    For Example,if the maximum incident parameter is set to 100, the 'on_poll' feature must incorporate up to 100 distinct incidents, based on the provided filter and start time parameter value.


## Configure and set up permissions of the app created on the Microsoft Azure portal

<div style="margin-left: 2em">

#### Create the app

1.  Navigate to <https://portal.azure.com> .
2.  Log in with a user that has permission to create an app in the Microsoft Entra ID.
3.  Select the 'Microsoft Entra ID'.
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
        -   SecurityIncident.ReadWrite.All

    -   **Delegated Permissions**

        -   SecurityAlert.Read.All
        -   SecurityAlert.ReadWrite.All
        -   ThreatHunting.Read.All
        -   SecurityIncident.Read.All
        -   SecurityIncident.ReadWrite.All

12. 'Grant Admin Consent' for it.
13. Again click on 'Add a permission'.
14. Under the 'Select an API' section, select 'Microsoft APIs'.
15. Click on the 'Microsoft Graph' option.
16. Provide the following Delegated permission to the app.
    -   **Delegated Permission**

        -   offline_access

#### Create a client secret or jump to next section to use Certificate Based Authentication

17. Select the 'Certificates & secrets' menu from the left-side panel.
18. Select 'New client secret' button to open a pop-up window.
19. Provide the description, select an appropriate option for deciding the client secret expiration
    time, and click on the 'Add' button.
20. Click 'Copy to clipboard' to copy the generated secret value and paste it in a safe place. You
    will need it to configure the asset and will not be able to retrieve it later.

#### Using Certificate Based Authentication
21. Select the 'Certificates & secrets' menu from the left-side panel.
22. Select the 'Certificates' tab.
23. Click 'Upload Certificate' and choose a '*.crt' file that contains the server certificate.
24. Select the 'Thumbprint' for the newly uploaded certificate and copy it somewhere to be
    used when configuring the SOAR app.

#### Copy your application id and tenant id

25. Select the 'Overview' menu from the left-side panel.
26. Copy the **Application (client) ID** and **Directory (tenant) ID** . You will need these to
    configure the SOAR asset.



## Configure the Microsoft 365 Defender SOAR app's asset

When creating an asset for the app,

-   Check the checkbox **Non-Interactive Auth** if you want to use Non-Interactive authentication
    mechanism otherwise Interactive auth mechanism will be used.

-   Provide the client ID of the app created during the previous step of app creation in the 'Client
    ID' field.

-   Provide the client secret of the app created during the previous step of app creation in the
    'Client Secret' field. -or- If using Certificate Based Authenticaion, do not not enter anything
    in this field, instead, complete the next three steps.

-   For Certificate Based Authentication only: Provide the 'Certificate Thumbprint' recorded above from Microsoft Entra.
-   For Certificate Based Authentication only: Provide the 'Certificate Private Key' (cut and paste the .pem file contents).
-   For Certificate Based Authentication only: Ensure the 'Non-Interactive Auth' checkbox is checked.

-   Provide the tenant ID of the app created during the previous step of Azure app creation in the
    'Tenant ID' field. For getting the value of tenant ID, navigate to the  Microsoft Entra ID; The value displayed in the 'Tenant ID'.

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
    2.  Navigate to the 'Microsoft Entra ID' on the Microsoft Azure portal.
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

      

    -   The first step is to get an application created in a specific tenant on the Microsoft Entra ID. Generate the \[client_secret\] for the configured application. The
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

- state file path on instance: /opt/phantom/local_data/app_states/\<appid>/\<asset_id>\_state.json

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
