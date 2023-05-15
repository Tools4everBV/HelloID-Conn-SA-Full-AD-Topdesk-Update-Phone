<!-- Description -->
## Description
This HelloID Service Automation Delegated Form provides updates for mobile and fixed phone numbers on an AD user account and Topdesk person. The following options are available:
 1. Search and select the target AD user account
 2. Show basic AD user account attributes of the selected target user
 3. Enter new values for the following AD user account attributes: OfficePhone and MobilePhone
 4. AD user account [OfficePhone and MobilePhone] and Topdesk person [phoneNumber and mobileNumber] attributes are updated with new values

## Versioning
| Version | Description | Date |
| - | - | - |
| 0.1.0   | First release | 2023/05/15  |

<!-- TABLE OF CONTENTS -->
## Table of Contents
* [Description](#description)
* [All-in-one PowerShell setup script](#all-in-one-powershell-setup-script)
  * [Getting started](#getting-started)
* [Post-setup configuration](#post-setup-configuration)
* [Manual resources](#manual-resources)
* [Add another system to update](#Add-another-system-to-update)
* [Getting help](#getting-help)
* [HelloID Docs](#HelloID-Docs)


## All-in-one PowerShell setup script
The PowerShell script "createform.ps1" contains a complete PowerShell script using the HelloID API to create the complete Form including user-defined variables, tasks and data sources.

 _Please note that this script assumes none of the required resources do exist within HelloID. The script does not contain versioning or source control_


### Getting started
Please follow the documentation steps on [HelloID Docs](https://docs.helloid.com/hc/en-us/articles/360017556559-Service-automation-GitHub-resources) in order to set up and run the All-in-one Powershell Script in your own environment.

 
## Post-setup configuration
After the all-in-one PowerShell script has run and created all the required resources. The following items need to be configured according to your own environment
 1. Update the following [user-defined variables](https://docs.helloid.com/hc/en-us/articles/360014169933-How-to-Create-and-Manage-User-Defined-Variables)
<table>
  <tr><td><strong>Variable name</strong></td><td><strong>Example value</strong></td><td><strong>Description</strong></td></tr>
  <tr><td>ADusersSearchOU</td><td>[{ "OU": "OU=Disabled Users,OU=HelloID Training,DC=veeken,DC=local"},{ "OU": "OU=Users,OU=HelloID Training,DC=veeken,DC=local"}]</td><td>Array of Active Directory OUs for scoping AD user accounts in the search result of this form</td></tr>
  <tr><td>TopdeskUrl</td><td>1</td><td>2</td></tr>
  <tr><td>TopdeskUsername</td><td>1</td><td>2</td></tr>
  <tr><td>TopdeskAPIkey</td><td>1</td><td>2</td></tr>
</table>

## Manual resources
This Delegated Form uses the following resources in order to run

### Powershell data source 'AD-AFAS-account-update-phone-lookup-user-generate-table'
This Powershell data source runs an Active Directory query to search for matching AD user accounts. It uses an array of Active Directory OU's specified as HelloID user-defined variable named _"ADusersSearchOU"_ to specify the search scope. This data source returns additional attributes that receive the current values for OfficePhone and MobilePhone.

### Powershell data source 'AD-AFAS-account-update-phone-table-user-details'
This Powershell data source runs an Active Directory query to select an extended list of user attributes of the selected AD user account.  

### Delegated form task 'AD AFAS Account - Update phone'
This delegated form task will update two systems. On the AD user account the attributes OfficePhone and MobilePhone will be updated. On the Topdesk person, the attributes phoneNumber and mobileNumber will be updated.

## Add another system to update
It is possible to add another system to update the mobile and fixed phone numbers. For example for AFAS employees. The following action steps are required to add another system:
1. Copy the global variables from the other git repository (for example the AFAS global variables)
2. Add the global variables to your HelloID tenant
3. Open the task from the other git repository and copy the region of the other system (for example region AFAS)
4. Add the region in the Task script

## Getting help
_If you need help, feel free to ask questions on our [forum](https://forum.helloid.com/forum/helloid-connectors/service-automation/)_

## HelloID Docs
The official HelloID documentation can be found at: https://docs.helloid.com/