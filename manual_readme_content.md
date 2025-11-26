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

     - Uncheck the **Non-Interactive Auth** checkbox.
     - After saving the asset, a new uneditable field will appear in the 'Asset Settings' tab. Copy the URL from the **POST incoming for Microsoft 365 Defender to this location** field and add a `/result` suffix to it. The resulting URL will look like this:
       `https://<soar_host/rest/handler/microsoft365defender_<appid/<asset_name/result`
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

- \<appid - The app ID will be available in the Redirect URI which gets populated in the field
  'POST incoming for Microsoft 365 Defender to this location' when the Microsoft 365 Defender app
  asset is configured e.g.
  https://\<splunk_soar_host/rest/handler/microsoft365defender\_\<appid/\<asset_name/result
- \<asset_id - The asset ID will be available on the created asset's Splunk SOAR web URL e.g.
  https://\<splunk_soar_host/apps/\<app_number/asset/\<asset_id/

#### The app is configured and ready to be used now.
