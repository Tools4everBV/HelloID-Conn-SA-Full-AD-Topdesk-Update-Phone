# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

#HelloID variables
#Note: when running this script inside HelloID; portalUrl and API credentials are provided automatically (generate and save API credentials first in your admin panel!)
$portalUrl = "https://CUSTOMER.helloid.com"
$apiKey = "API_KEY"
$apiSecret = "API_SECRET"
$delegatedFormAccessGroupNames = @("") #Only unique names are supported. Groups must exist!
$delegatedFormCategories = @("Active Directory","User Management") #Only unique names are supported. Categories will be created if not exists
$script:debugLogging = $false #Default value: $false. If $true, the HelloID resource GUIDs will be shown in the logging
$script:duplicateForm = $false #Default value: $false. If $true, the HelloID resource names will be changed to import a duplicate Form
$script:duplicateFormSuffix = "_tmp" #the suffix will be added to all HelloID resource names to generate a duplicate form with different resource names

#The following HelloID Global variables are used by this form. No existing HelloID global variables will be overriden only new ones are created.
#NOTE: You can also update the HelloID Global variable values afterwards in the HelloID Admin Portal: https://<CUSTOMER>.helloid.com/admin/variablelibrary
$globalHelloIDVariables = [System.Collections.Generic.List[object]]@();

#Global variable #1 >> TopdeskAPIkey
$tmpName = @'
TopdeskAPIkey
'@ 
$tmpValue = "" 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "True"});

#Global variable #2 >> TopdeskUsername
$tmpName = @'
TopdeskUsername
'@ 
$tmpValue = "" 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});

#Global variable #3 >> TopdeskUrl
$tmpName = @'
TopdeskUrl
'@ 
$tmpValue = @'
https://customer.topdesk.net
'@ 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});

#Global variable #4 >> ADusersSearchOU
$tmpName = @'
ADusersSearchOU
'@ 
$tmpValue = @'
[{ "OU": "OU=Disabled Users,OU=HelloID Training,DC=veeken,DC=local"},{ "OU": "OU=Users,OU=HelloID Training,DC=veeken,DC=local"}]
'@ 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});


#make sure write-information logging is visual
$InformationPreference = "continue"

# Check for prefilled API Authorization header
if (-not [string]::IsNullOrEmpty($portalApiBasic)) {
    $script:headers = @{"authorization" = $portalApiBasic}
    Write-Information "Using prefilled API credentials"
} else {
    # Create authorization headers with HelloID API key
    $pair = "$apiKey" + ":" + "$apiSecret"
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
    $base64 = [System.Convert]::ToBase64String($bytes)
    $key = "Basic $base64"
    $script:headers = @{"authorization" = $Key}
    Write-Information "Using manual API credentials"
}

# Check for prefilled PortalBaseURL
if (-not [string]::IsNullOrEmpty($portalBaseUrl)) {
    $script:PortalBaseUrl = $portalBaseUrl
    Write-Information "Using prefilled PortalURL: $script:PortalBaseUrl"
} else {
    $script:PortalBaseUrl = $portalUrl
    Write-Information "Using manual PortalURL: $script:PortalBaseUrl"
}

# Define specific endpoint URI
$script:PortalBaseUrl = $script:PortalBaseUrl.trim("/") + "/"  

# Make sure to reveive an empty array using PowerShell Core
function ConvertFrom-Json-WithEmptyArray([string]$jsonString) {
    # Running in PowerShell Core?
    if($IsCoreCLR -eq $true){
        $r = [Object[]]($jsonString | ConvertFrom-Json -NoEnumerate)
        return ,$r  # Force return value to be an array using a comma
    } else {
        $r = [Object[]]($jsonString | ConvertFrom-Json)
        return ,$r  # Force return value to be an array using a comma
    }
}

function Invoke-HelloIDGlobalVariable {
    param(
        [parameter(Mandatory)][String]$Name,
        [parameter(Mandatory)][String][AllowEmptyString()]$Value,
        [parameter(Mandatory)][String]$Secret
    )

    $Name = $Name + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    try {
        $uri = ($script:PortalBaseUrl + "api/v1/automation/variables/named/$Name")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
    
        if ([string]::IsNullOrEmpty($response.automationVariableGuid)) {
            #Create Variable
            $body = @{
                name     = $Name;
                value    = $Value;
                secret   = $Secret;
                ItemType = 0;
            }    
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
            $uri = ($script:PortalBaseUrl + "api/v1/automation/variable")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
            $variableGuid = $response.automationVariableGuid

            Write-Information "Variable '$Name' created$(if ($script:debugLogging -eq $true) { ": " + $variableGuid })"
        } else {
            $variableGuid = $response.automationVariableGuid
            Write-Warning "Variable '$Name' already exists$(if ($script:debugLogging -eq $true) { ": " + $variableGuid })"
        }
    } catch {
        Write-Error "Variable '$Name', message: $_"
    }
}

function Invoke-HelloIDAutomationTask {
    param(
        [parameter(Mandatory)][String]$TaskName,
        [parameter(Mandatory)][String]$UseTemplate,
        [parameter(Mandatory)][String]$AutomationContainer,
        [parameter(Mandatory)][String][AllowEmptyString()]$Variables,
        [parameter(Mandatory)][String]$PowershellScript,
        [parameter()][String][AllowEmptyString()]$ObjectGuid,
        [parameter()][String][AllowEmptyString()]$ForceCreateTask,
        [parameter(Mandatory)][Ref]$returnObject
    )
    
    $TaskName = $TaskName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    try {
        $uri = ($script:PortalBaseUrl +"api/v1/automationtasks?search=$TaskName&container=$AutomationContainer")
        $responseRaw = (Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false) 
        $response = $responseRaw | Where-Object -filter {$_.name -eq $TaskName}
    
        if([string]::IsNullOrEmpty($response.automationTaskGuid) -or $ForceCreateTask -eq $true) {
            #Create Task

            $body = @{
                name                = $TaskName;
                useTemplate         = $UseTemplate;
                powerShellScript    = $PowershellScript;
                automationContainer = $AutomationContainer;
                objectGuid          = $ObjectGuid;
                variables           = (ConvertFrom-Json-WithEmptyArray($Variables));
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
            $uri = ($script:PortalBaseUrl +"api/v1/automationtasks/powershell")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
            $taskGuid = $response.automationTaskGuid

            Write-Information "Powershell task '$TaskName' created$(if ($script:debugLogging -eq $true) { ": " + $taskGuid })"
        } else {
            #Get TaskGUID
            $taskGuid = $response.automationTaskGuid
            Write-Warning "Powershell task '$TaskName' already exists$(if ($script:debugLogging -eq $true) { ": " + $taskGuid })"
        }
    } catch {
        Write-Error "Powershell task '$TaskName', message: $_"
    }

    $returnObject.Value = $taskGuid
}

function Invoke-HelloIDDatasource {
    param(
        [parameter(Mandatory)][String]$DatasourceName,
        [parameter(Mandatory)][String]$DatasourceType,
        [parameter(Mandatory)][String][AllowEmptyString()]$DatasourceModel,
        [parameter()][String][AllowEmptyString()]$DatasourceStaticValue,
        [parameter()][String][AllowEmptyString()]$DatasourcePsScript,        
        [parameter()][String][AllowEmptyString()]$DatasourceInput,
        [parameter()][String][AllowEmptyString()]$AutomationTaskGuid,
        [parameter(Mandatory)][Ref]$returnObject
    )

    $DatasourceName = $DatasourceName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    $datasourceTypeName = switch($DatasourceType) { 
        "1" { "Native data source"; break} 
        "2" { "Static data source"; break} 
        "3" { "Task data source"; break} 
        "4" { "Powershell data source"; break}
    }
    
    try {
        $uri = ($script:PortalBaseUrl +"api/v1/datasource/named/$DatasourceName")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
      
        if([string]::IsNullOrEmpty($response.dataSourceGUID)) {
            #Create DataSource
            $body = @{
                name               = $DatasourceName;
                type               = $DatasourceType;
                model              = (ConvertFrom-Json-WithEmptyArray($DatasourceModel));
                automationTaskGUID = $AutomationTaskGuid;
                value              = (ConvertFrom-Json-WithEmptyArray($DatasourceStaticValue));
                script             = $DatasourcePsScript;
                input              = (ConvertFrom-Json-WithEmptyArray($DatasourceInput));
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
      
            $uri = ($script:PortalBaseUrl +"api/v1/datasource")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
              
            $datasourceGuid = $response.dataSourceGUID
            Write-Information "$datasourceTypeName '$DatasourceName' created$(if ($script:debugLogging -eq $true) { ": " + $datasourceGuid })"
        } else {
            #Get DatasourceGUID
            $datasourceGuid = $response.dataSourceGUID
            Write-Warning "$datasourceTypeName '$DatasourceName' already exists$(if ($script:debugLogging -eq $true) { ": " + $datasourceGuid })"
        }
    } catch {
      Write-Error "$datasourceTypeName '$DatasourceName', message: $_"
    }

    $returnObject.Value = $datasourceGuid
}

function Invoke-HelloIDDynamicForm {
    param(
        [parameter(Mandatory)][String]$FormName,
        [parameter(Mandatory)][String]$FormSchema,
        [parameter(Mandatory)][Ref]$returnObject
    )
    
    $FormName = $FormName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    try {
        try {
            $uri = ($script:PortalBaseUrl +"api/v1/forms/$FormName")
            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        } catch {
            $response = $null
        }
    
        if(([string]::IsNullOrEmpty($response.dynamicFormGUID)) -or ($response.isUpdated -eq $true)) {
            #Create Dynamic form
            $body = @{
                Name       = $FormName;
                FormSchema = (ConvertFrom-Json-WithEmptyArray($FormSchema));
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
            $uri = ($script:PortalBaseUrl +"api/v1/forms")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
    
            $formGuid = $response.dynamicFormGUID
            Write-Information "Dynamic form '$formName' created$(if ($script:debugLogging -eq $true) { ": " + $formGuid })"
        } else {
            $formGuid = $response.dynamicFormGUID
            Write-Warning "Dynamic form '$FormName' already exists$(if ($script:debugLogging -eq $true) { ": " + $formGuid })"
        }
    } catch {
        Write-Error "Dynamic form '$FormName', message: $_"
    }

    $returnObject.Value = $formGuid
}


function Invoke-HelloIDDelegatedForm {
    param(
        [parameter(Mandatory)][String]$DelegatedFormName,
        [parameter(Mandatory)][String]$DynamicFormGuid,
        [parameter()][Array][AllowEmptyString()]$AccessGroups,
        [parameter()][String][AllowEmptyString()]$Categories,
        [parameter(Mandatory)][String]$UseFaIcon,
        [parameter()][String][AllowEmptyString()]$FaIcon,
        [parameter()][String][AllowEmptyString()]$task,
        [parameter(Mandatory)][Ref]$returnObject
    )
    $delegatedFormCreated = $false
    $DelegatedFormName = $DelegatedFormName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    try {
        try {
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms/$DelegatedFormName")
            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        } catch {
            $response = $null
        }
    
        if([string]::IsNullOrEmpty($response.delegatedFormGUID)) {
            #Create DelegatedForm
            $body = @{
                name            = $DelegatedFormName;
                dynamicFormGUID = $DynamicFormGuid;
                isEnabled       = "True";
                useFaIcon       = $UseFaIcon;
                faIcon          = $FaIcon;
                task            = ConvertFrom-Json -inputObject $task;
            }
            if(-not[String]::IsNullOrEmpty($AccessGroups)) { 
                $body += @{
                    accessGroups    = (ConvertFrom-Json-WithEmptyArray($AccessGroups));
                }
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
    
            $delegatedFormGuid = $response.delegatedFormGUID
            Write-Information "Delegated form '$DelegatedFormName' created$(if ($script:debugLogging -eq $true) { ": " + $delegatedFormGuid })"
            $delegatedFormCreated = $true

            $bodyCategories = $Categories
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms/$delegatedFormGuid/categories")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $bodyCategories
            Write-Information "Delegated form '$DelegatedFormName' updated with categories"
        } else {
            #Get delegatedFormGUID
            $delegatedFormGuid = $response.delegatedFormGUID
            Write-Warning "Delegated form '$DelegatedFormName' already exists$(if ($script:debugLogging -eq $true) { ": " + $delegatedFormGuid })"
        }
    } catch {
        Write-Error "Delegated form '$DelegatedFormName', message: $_"
    }

    $returnObject.value.guid = $delegatedFormGuid
    $returnObject.value.created = $delegatedFormCreated
}


<# Begin: HelloID Global Variables #>
foreach ($item in $globalHelloIDVariables) {
	Invoke-HelloIDGlobalVariable -Name $item.name -Value $item.value -Secret $item.secret 
}
<# End: HelloID Global Variables #>


<# Begin: HelloID Data sources #>
<# Begin: DataSource "AD-Topdesk-account-update-phone-table-user-details" #>
$tmpPsScript = @'
#######################################################################
# Template: RHo HelloID SA Powershell data source
# Name:     AD-Topdesk-account-update-phone-table-user-details
# Date:     15-05-2023
#######################################################################

# For basic information about powershell data sources see:
# https://docs.helloid.com/en/service-automation/dynamic-forms/data-sources/powershell-data-sources/add,-edit,-or-remove-a-powershell-data-source.html#add-a-powershell-data-source

# Service automation variables:
# https://docs.helloid.com/en/service-automation/service-automation-variables/service-automation-variable-reference.html

#region init

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# global variables (Automation --> Variable libary):
# $globalVar = $globalVarName

# variables configured in form:
$userPrincipalName = $dataSource.selectedUser.UserPrincipalName

#endregion init

#region functions

#endregion functions

#region lookup
try {
    Write-Information "Searching AD user [$userPrincipalName]"
    
    $user = Get-ADuser -Filter { UserPrincipalName -eq $userPrincipalName } -Properties displayname, userPrincipalName, officePhone, mobilePhone, mail, employeeID | Select-Object employeeID, displayname, userPrincipalName, mail, officePhone, mobilePhone
    Write-Information -Message "Successfully queried data. AD user [$userPrincipalName]"

    if (($user | Measure-Object).Count -gt 0) {
        foreach ($property in $user.psObject.properties) {
            $returnObject = @{
                name=$property.Name
                value=$property.value
            }    
            Write-Output $returnObject      
        }
    }
}
catch {
    $ex = $PSItem
    Write-Verbose "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
        
    Write-Error "Error querying data. Error Message: $($_ex.Exception.Message)" 
}
#endregion lookup
'@ 
$tmpModel = @'
[{"key":"name","type":0},{"key":"value","type":0}]
'@ 
$tmpInput = @'
[{"description":null,"translateDescription":false,"inputFieldType":1,"key":"selectedUser","type":0,"options":1}]
'@ 
$dataSourceGuid_1 = [PSCustomObject]@{} 
$dataSourceGuid_1_Name = @'
AD-Topdesk-account-update-phone-table-user-details
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_1_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_1) 
<# End: DataSource "AD-Topdesk-account-update-phone-table-user-details" #>

<# Begin: DataSource "AD-Topdesk-account-update-phone-lookup-user-generate-table" #>
$tmpPsScript = @'
#######################################################################
# Template: RHo HelloID SA Powershell data source
# Name:     AD-Topdesk-account-update-phone-lookup-user-generate-table
# Date:     15-05-2023
#######################################################################

# For basic information about powershell data sources see:
# https://docs.helloid.com/en/service-automation/dynamic-forms/data-sources/powershell-data-sources/add,-edit,-or-remove-a-powershell-data-source.html#add-a-powershell-data-source

# Service automation variables:
# https://docs.helloid.com/en/service-automation/service-automation-variables/service-automation-variable-reference.html

#region init

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# global variables (Automation --> Variable libary):
$searchOUs = $ADusersSearchOU

# variables configured in form:
$searchValue = $dataSource.searchUser
$searchQuery = "*$searchValue*"

#endregion init

#region functions

#endregion functions

#region lookup
try {
    Write-Verbose "Querying data"

    if ([String]::IsNullOrEmpty($searchValue) -eq $true) {
        return
    }
    else {
        Write-Information "SearchQuery: $searchQuery"
        Write-Information "SearchBase: $searchOUs"
        
        $ous = $searchOUs | ConvertFrom-Json
        $users = foreach ($item in $ous) {
            Get-ADUser -Filter { Name -like $searchQuery -or DisplayName -like $searchQuery -or userPrincipalName -like $searchQuery -or mail -like $searchQuery -or EmployeeID -like $searchQuery } -SearchBase $item.ou -properties SamAccountName, displayName, UserPrincipalName, mobilePhone, officePhone, EmployeeID
        }
    

        $users = $users | Where-Object { $null -ne $_.employeeID }
        $users = $users | Sort-Object -Property DisplayName

        if (($users | Measure-Object).Count -gt 0) {
            foreach ($user in $users) {
                $returnObject = @{
                    SamAccountName    = $user.SamAccountName
                    displayName       = $user.displayName
                    UserPrincipalName = $user.UserPrincipalName
                    EmployeeID        = $user.EmployeeID
                    MobilePhone       = $user.MobilePhone
                    OfficePhone       = $user.OfficePhone
                }    
                Write-Output $returnObject      
            }
        }
    }
}
catch {
    $ex = $PSItem
    Write-Verbose "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
        
    Write-Error "Error retrieving AD user [$userPrincipalName] basic attributes. Error: $($_.Exception.Message)"
}
#endregion lookup
'@ 
$tmpModel = @'
[{"key":"OfficePhone","type":0},{"key":"MobilePhone","type":0},{"key":"EmployeeID","type":0},{"key":"UserPrincipalName","type":0},{"key":"SamAccountName","type":0},{"key":"displayName","type":0}]
'@ 
$tmpInput = @'
[{"description":null,"translateDescription":false,"inputFieldType":1,"key":"searchUser","type":0,"options":1}]
'@ 
$dataSourceGuid_0 = [PSCustomObject]@{} 
$dataSourceGuid_0_Name = @'
AD-Topdesk-account-update-phone-lookup-user-generate-table
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_0_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_0) 
<# End: DataSource "AD-Topdesk-account-update-phone-lookup-user-generate-table" #>
<# End: HelloID Data sources #>

<# Begin: Dynamic Form "AD Topdesk Account - Update phone" #>
$tmpSchema = @"
[{"label":"Select user account","fields":[{"key":"searchfield","templateOptions":{"label":"Search","placeholder":"Username or email address"},"type":"input","summaryVisibility":"Hide element","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"gridUsers","templateOptions":{"label":"Select user account","required":true,"grid":{"columns":[{"headerName":"Employee ID","field":"EmployeeID"},{"headerName":"Display Name","field":"displayName"},{"headerName":"User Principal Name","field":"UserPrincipalName"},{"headerName":"Sam Account Name","field":"SamAccountName"},{"headerName":"Mobile Phone","field":"MobilePhone"},{"headerName":"Office Phone","field":"OfficePhone"}],"height":300,"rowSelection":"single"},"dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_0","input":{"propertyInputs":[{"propertyName":"searchUser","otherFieldValue":{"otherFieldKey":"searchfield"}}]}},"useFilter":false},"type":"grid","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":true}]},{"label":"Details","fields":[{"key":"gridDetails","templateOptions":{"label":"Basic attributes","required":false,"grid":{"columns":[{"headerName":"Name","field":"name"},{"headerName":"Value","field":"value"}],"height":310,"rowSelection":"single"},"dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_1","input":{"propertyInputs":[{"propertyName":"selectedUser","otherFieldValue":{"otherFieldKey":"gridUsers"}}]}},"useFilter":false},"type":"grid","summaryVisibility":"Hide element","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":true},{"key":"mobilePhone","templateOptions":{"label":"Mobile work","pattern":"^(06-)+[0-9]{8}$","useDependOn":true,"dependOn":"gridUsers","dependOnProperty":"MobilePhone"},"validation":{"messages":{"pattern":"Please fill in the mobile number in the following format: 06-12345678"}},"type":"input","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"officePhone","templateOptions":{"label":"Fixed work","pattern":"^(088-123)+[0-9]{4}$","useDependOn":true,"dependOn":"gridUsers","dependOnProperty":"OfficePhone"},"validation":{"messages":{"pattern":"Please fill in the mobile number in the following format: 088-123xxxx"}},"type":"input","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false}]}]
"@ 

$dynamicFormGuid = [PSCustomObject]@{} 
$dynamicFormName = @'
AD Topdesk Account - Update phone
'@ 
Invoke-HelloIDDynamicForm -FormName $dynamicFormName -FormSchema $tmpSchema  -returnObject ([Ref]$dynamicFormGuid) 
<# END: Dynamic Form #>

<# Begin: Delegated Form Access Groups and Categories #>
$delegatedFormAccessGroupGuids = @()
if(-not[String]::IsNullOrEmpty($delegatedFormAccessGroupNames)){
    foreach($group in $delegatedFormAccessGroupNames) {
        try {
            $uri = ($script:PortalBaseUrl +"api/v1/groups/$group")
            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
            $delegatedFormAccessGroupGuid = $response.groupGuid
            $delegatedFormAccessGroupGuids += $delegatedFormAccessGroupGuid
            
            Write-Information "HelloID (access)group '$group' successfully found$(if ($script:debugLogging -eq $true) { ": " + $delegatedFormAccessGroupGuid })"
        } catch {
            Write-Error "HelloID (access)group '$group', message: $_"
        }
    }
    if($null -ne $delegatedFormAccessGroupGuids){
        $delegatedFormAccessGroupGuids = ($delegatedFormAccessGroupGuids | Select-Object -Unique | ConvertTo-Json -Depth 100 -Compress)
    }
}

$delegatedFormCategoryGuids = @()
foreach($category in $delegatedFormCategories) {
    try {
        $uri = ($script:PortalBaseUrl +"api/v1/delegatedformcategories/$category")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        $response = $response | Where-Object {$_.name.en -eq $category}
        
        $tmpGuid = $response.delegatedFormCategoryGuid
        $delegatedFormCategoryGuids += $tmpGuid
        
        Write-Information "HelloID Delegated Form category '$category' successfully found$(if ($script:debugLogging -eq $true) { ": " + $tmpGuid })"
    } catch {
        Write-Warning "HelloID Delegated Form category '$category' not found"
        $body = @{
            name = @{"en" = $category};
        }
        $body = ConvertTo-Json -InputObject $body -Depth 100

        $uri = ($script:PortalBaseUrl +"api/v1/delegatedformcategories")
        $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
        $tmpGuid = $response.delegatedFormCategoryGuid
        $delegatedFormCategoryGuids += $tmpGuid

        Write-Information "HelloID Delegated Form category '$category' successfully created$(if ($script:debugLogging -eq $true) { ": " + $tmpGuid })"
    }
}
$delegatedFormCategoryGuids = (ConvertTo-Json -InputObject $delegatedFormCategoryGuids -Depth 100 -Compress)
<# End: Delegated Form Access Groups and Categories #>

<# Begin: Delegated Form #>
$delegatedFormRef = [PSCustomObject]@{guid = $null; created = $null} 
$delegatedFormName = @'
AD Topdesk Account - Update phone
'@
$tmpTask = @'
{"name":"AD Topdesk Account - Update phone","script":"#######################################################################\r\n# Template: RHo HelloID SA Delegated form task\r\n# Name:     AD-Topdesk-account-update-phone\r\n# Date:     15-05-2023\r\n#######################################################################\r\n\r\n# For basic information about delegated form tasks see:\r\n# https://docs.helloid.com/en/service-automation/delegated-forms/delegated-form-powershell-scripts/add-a-powershell-script-to-a-delegated-form.html\r\n\r\n# Service automation variables:\r\n# https://docs.helloid.com/en/service-automation/service-automation-variables/service-automation-variable-reference.html\r\n\r\n#region init\r\n# Set TLS to accept TLS, TLS 1.1 and TLS 1.2\r\n[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12\r\n\r\n$VerbosePreference = \"SilentlyContinue\"\r\n$InformationPreference = \"Continue\"\r\n$WarningPreference = \"Continue\"\r\n\r\n# global variables (Automation --> Variable libary):\r\n# $globalVar = $globalVarName\r\n\r\n# variables configured in form:\r\n$userPrincipalName = $form.gridUsers.UserPrincipalName\r\n$phoneMobile = $form.mobilePhone\r\n$phoneFixed = $form.officePhone\r\n$employeeID = $form.gridUsers.employeeID\r\n$displayName = $form.gridUsers.displayName\r\n#endregion init\r\n\r\n#region global functions\r\nfunction Resolve-HTTPError {\r\n    [CmdletBinding()]\r\n    param (\r\n        [Parameter(Mandatory,\r\n            ValueFromPipeline\r\n        )]\r\n        [object]$ErrorObject\r\n    )\r\n    process {\r\n        $httpErrorObj = [PSCustomObject]@{\r\n            FullyQualifiedErrorId = $ErrorObject.FullyQualifiedErrorId\r\n            MyCommand             = $ErrorObject.InvocationInfo.MyCommand\r\n            RequestUri            = $ErrorObject.TargetObject.RequestUri\r\n            ScriptStackTrace      = $ErrorObject.ScriptStackTrace\r\n            ErrorMessage          = ''\r\n        }\r\n        if ($ErrorObject.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') {\r\n            $httpErrorObj.ErrorMessage = $ErrorObject.ErrorDetails.Message\r\n        }\r\n        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {\r\n            $httpErrorObj.ErrorMessage = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()\r\n        }\r\n        Write-Output $httpErrorObj\r\n    }\r\n}\r\n#endregion global functions\r\n\r\n#region AD\r\ntry {\r\n    Write-Information \"Querying AD user [$userPrincipalName]\"\r\n    $adUser = Get-ADuser -Filter { UserPrincipalName -eq $userPrincipalName } \r\n    Write-Information \"Found AD user [$userPrincipalName]\"\r\n}\r\ncatch {\r\n    Write-Error \"Could not find AD user [$userPrincipalName]. Error: $($_.Exception.Message)\"    \r\n    $Log = @{\r\n        Action            = \"UpdateAccount\" # optional. ENUM (undefined = default) \r\n        System            = \"ActiveDirectory\" # optional (free format text) \r\n        Message           = \"Could not find AD user [$userPrincipalName]. Error: $($_.Exception.Message)\" # required (free format text) \r\n        IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n        TargetDisplayName = $displayName # optional (free format text) \r\n        TargetIdentifier  = $([string]$adUser.SID) # optional (free format text) \r\n    }\r\n    #send result back  \r\n    Write-Information -Tags \"Audit\" -MessageData $log  \r\n}\r\ntry {\r\n    Write-Information \"Start updating AD user [$userPrincipalName]\"\r\n    if ([String]::IsNullOrEmpty($phoneMobile) -eq $true) {\r\n        Set-ADUser -Identity $adUSer -MobilePhone $null\r\n    }\r\n    else {\r\n        Set-ADUser -Identity $adUSer -MobilePhone $phoneMobile\r\n    }\r\n\r\n    if ([String]::IsNullOrEmpty($phoneFixed) -eq $true) {\r\n        Set-ADUser -Identity $adUSer -OfficePhone $null\r\n    }\r\n    else {\r\n        Set-ADUser -Identity $adUSer -OfficePhone $phoneFixed\r\n    }\r\n    \r\n    Write-Information \"Finished update attribute [phoneMobile] of AD user [$userPrincipalName] to [$phoneMobile] and/or [officePhone] to [$phoneFixed]\"\r\n    $Log = @{\r\n        Action            = \"UpdateAccount\" # optional. ENUM (undefined = default) \r\n        System            = \"ActiveDirectory\" # optional (free format text) \r\n        Message           = \"Successfully updated attribute [phoneMobile] of AD user [$userPrincipalName] to [$phoneMobile] and/or [officePhone] to [$phoneFixed]\" # required (free format text) \r\n        IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n        TargetDisplayName = $adUser.name # optional (free format text) \r\n        TargetIdentifier  = $([string]$adUser.SID) # optional (free format text) \r\n    }\r\n    #send result back  \r\n    Write-Information -Tags \"Audit\" -MessageData $log    \r\n}\r\ncatch {\r\n    Write-Error \"Could not update attribute [phoneMobile] of AD user [$userPrincipalName] to [$phoneMobile] and/or [officePhone] to [$phoneFixed]. Error: $($_.Exception.Message)\"\r\n    $Log = @{\r\n        Action            = \"UpdateAccount\" # optional. ENUM (undefined = default) \r\n        System            = \"ActiveDirectory\" # optional (free format text) \r\n        Message           = \"Failed to update attribute [phoneMobile] of AD user [$userPrincipalName] to [$phoneMobile] and/or [officePhone] to [$phoneFixed]\" # required (free format text) \r\n        IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n        TargetDisplayName = $adUser.name # optional (free format text) \r\n        TargetIdentifier  = $([string]$adUser.SID) # optional (free format text) \r\n    }\r\n    #send result back  \r\n    Write-Information -Tags \"Audit\" -MessageData $log      \r\n}\r\n#endregion AD\r\n\r\n#region Topdesk\r\nfunction Set-AuthorizationHeaders {\r\n    [CmdletBinding()]\r\n    param (\r\n        [Parameter(Mandatory)]\r\n        [ValidateNotNullOrEmpty()]\r\n        [string]\r\n        $Username,\r\n\r\n        [Parameter(Mandatory)]\r\n        [ValidateNotNullOrEmpty()]\r\n        [string]\r\n        $ApiKey\r\n    )\r\n    # Create basic authentication string\r\n    $bytes = [System.Text.Encoding]::ASCII.GetBytes(\"${Username}:${Apikey}\")\r\n    $base64 = [System.Convert]::ToBase64String($bytes)\r\n\r\n    # Set authentication headers\r\n    $authHeaders = [System.Collections.Generic.Dictionary[string, string]]::new()\r\n    $authHeaders.Add(\"Authorization\", \"BASIC $base64\")\r\n    $authHeaders.Add(\"Accept\", 'application/json')\r\n\r\n    Write-Output $authHeaders\r\n}\r\n\r\nfunction Invoke-TopdeskRestMethod {\r\n    [CmdletBinding()]\r\n    param (\r\n        [Parameter(Mandatory)]\r\n        [ValidateNotNullOrEmpty()]\r\n        [string]\r\n        $Method,\r\n\r\n        [Parameter(Mandatory)]\r\n        [ValidateNotNullOrEmpty()]\r\n        [string]\r\n        $Uri,\r\n\r\n        [object]\r\n        $Body,\r\n\r\n        [string]\r\n        $ContentType = 'application/json; charset=utf-8',\r\n\r\n        [Parameter(Mandatory)]\r\n        [System.Collections.IDictionary]\r\n        $Headers\r\n    )\r\n    process {\r\n        try {\r\n            $splatParams = @{\r\n                Uri         = $Uri\r\n                Headers     = $Headers\r\n                Method      = $Method\r\n                ContentType = $ContentType\r\n            }\r\n            if ($Body) {\r\n                $splatParams['Body'] = [Text.Encoding]::UTF8.GetBytes($Body)\r\n            }\r\n            Invoke-RestMethod @splatParams -Verbose:$false\r\n        }\r\n        catch {\r\n            $PSCmdlet.ThrowTerminatingError($_)\r\n        }\r\n    }\r\n}\r\n\r\nfunction Get-TopdeskPersonByCorrelationAttribute {\r\n    [CmdletBinding()]\r\n    param (\r\n        [Parameter(Mandatory)]\r\n        [ValidateNotNullOrEmpty()]\r\n        [string]\r\n        $BaseUrl,\r\n\r\n        [Parameter(Mandatory)]\r\n        [System.Collections.IDictionary]\r\n        $Headers,\r\n\r\n        [Parameter(Mandatory)]\r\n        [ValidateNotNullOrEmpty()]\r\n        [Object]\r\n        $Account,\r\n\r\n        [Parameter(Mandatory)]\r\n        [ValidateNotNullOrEmpty()]\r\n        [String]\r\n        $CorrelationAttribute\r\n    )\r\n\r\n    # Check if the correlation attribute exists in the account object set in the mapping\r\n    if (-not([bool]$account.PSObject.Properties[$CorrelationAttribute])) {\r\n        $errorMessage = \"The correlation attribute [$CorrelationAttribute] is missing in the account mapping. This is a scripting issue.\"\r\n        throw $errorMessage\r\n    }\r\n\r\n    # Check if the correlationAttribute is not empty\r\n    if ([string]::IsNullOrEmpty($account.$CorrelationAttribute)) {\r\n        $errorMessage = \"The correlation attribute [$CorrelationAttribute] is empty. This is likely a scripting issue.\"\r\n        throw $errorMessage\r\n    }\r\n\r\n    # Lookup value is filled in, lookup value in Topdesk\r\n    $splatParams = @{\r\n        Uri     = \"$baseUrl/tas/api/persons?page_size=2&query=$($correlationAttribute)=='$($account.$CorrelationAttribute)'\"\r\n        Method  = 'GET'\r\n        Headers = $Headers\r\n    }\r\n    write-verbose ($splatParams | ConvertTo-Json)\r\n    $responseGet = Invoke-TopdeskRestMethod @splatParams\r\n\r\n    # Check if only one result is returned\r\n    if ([string]::IsNullOrEmpty($responseGet.id)) {\r\n        # no results found\r\n        # Multiple records found, correlation\r\n        $errorMessage = \"No person found with [$CorrelationAttribute] [$($account.$CorrelationAttribute)]\"\r\n        throw $errorMessage\r\n    }\r\n    elseif ($responseGet.Count -eq 1) {\r\n        # one record found, correlate, return user\r\n        write-output $responseGet\r\n    }\r\n    else {\r\n        # Multiple records found, correlation\r\n        $errorMessage = \"Multiple [$($responseGet.Count)] persons found with [$CorrelationAttribute] [$($account.$CorrelationAttribute)]. Login names: [$($responseGet.tasLoginName)]\"\r\n        throw $errorMessage\r\n    }\r\n}\r\n\r\nfunction Set-TopdeskPerson {\r\n    [CmdletBinding()]\r\n    param (\r\n        [Parameter(Mandatory)]\r\n        [ValidateNotNullOrEmpty()]\r\n        [string]\r\n        $BaseUrl,\r\n\r\n        [Parameter(Mandatory)]\r\n        [System.Collections.IDictionary]\r\n        $Headers,\r\n\r\n        [Parameter(Mandatory)]\r\n        [ValidateNotNullOrEmpty()]\r\n        [Object]\r\n        $Account,\r\n\r\n        [Parameter(Mandatory)]\r\n        [ValidateNotNullOrEmpty()]\r\n        [Object]\r\n        $TopdeskPerson\r\n    )\r\n\r\n    Write-Verbose \"Updating person\"\r\n    $splatParams = @{\r\n        Uri     = \"$BaseUrl/tas/api/persons/id/$($TopdeskPerson.id)\"\r\n        Method  = 'PATCH'\r\n        Headers = $Headers\r\n        Body    = $Account | ConvertTo-Json\r\n    }\r\n    # Write-Information ($splatParams | ConvertTo-Json)\r\n    $null = Invoke-TopdeskRestMethod @splatParams\r\n}\r\n\r\ntry {\r\n    $username = $TopdeskUsername\r\n    $apikey = $TopdeskAPIkey\r\n    $baseUrl = $TopdeskUrl\r\n\r\n    # Account mapping. See for all possible options the Topdesk 'supporting files' API documentation at\r\n    # https://developers.topdesk.com/explorer/?page=supporting-files#/Persons/createPerson\r\n    $account = [PSCustomObject]@{\r\n        employeeNumber = $employeeID\r\n        mobileNumber   = $phoneMobile\r\n        phoneNumber    = $phoneFixed\r\n    }\r\n\r\n    $correlationAttribute = 'employeeNumber'\r\n\r\n    \r\n    $action = 'Process'\r\n\r\n    Write-Information \"Querying Topdesk person [$employeeID]\"\r\n\r\n    # Setup authentication headers\r\n    $authHeaders = Set-AuthorizationHeaders -UserName $username -ApiKey $apiKey\r\n\r\n    # get person\r\n    $splatParamsPerson = @{\r\n        Account              = $account\r\n        CorrelationAttribute = $correlationAttribute\r\n        Headers              = $authHeaders\r\n        BaseUrl              = $baseUrl\r\n    }\r\n    $TopdeskPerson = Get-TopdeskPersonByCorrelationAttribute @splatParamsPerson\r\n\r\n    Write-Information \"Found Topdesk person [$employeeID]\"\r\n\r\n    $action = 'Update'\r\n\r\n    Write-Information \"Start updating Topdesk person [$employeeID]\"\r\n\r\n    # Update TOPdesk person\r\n    $splatParamsPersonUpdate = @{\r\n        TopdeskPerson = $TopdeskPerson\r\n        Account       = $account\r\n        Headers       = $authHeaders\r\n        BaseUrl       = $baseUrl\r\n    }\r\n    Set-TopdeskPerson @splatParamsPersonUpdate\r\n\r\n    Write-Information \"Finished update attribute [mobileNumber] of Topdesk user [$($TopdeskPerson.id)] to [$phoneMobile] and/or [phoneNumber] to [$phoneFixed]\"\r\n    $Log = @{\r\n        Action            = \"UpdateAccount\" # optional. ENUM (undefined = default) \r\n        System            = \"Topdesk\" # optional (free format text) \r\n        Message           = \"Successfully updated attribute [mobileNumber] of Topdesk user [$($TopdeskPerson.id)] to [$phoneMobile] and/or [phoneNumber] to [$phoneFixed]\" # required (free format text) \r\n        IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n        TargetDisplayName = $displayName # optional (free format text) \r\n        TargetIdentifier  = $([string]$TopdeskPerson.id) # optional (free format text) \r\n    }\r\n    #send result back  \r\n    Write-Information -Tags \"Audit\" -MessageData $log\r\n}\r\ncatch {\r\n    $ex = $PSItem\r\n    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or\r\n        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {\r\n        if (-Not [string]::IsNullOrEmpty($ex.ErrorDetails.Message)) {\r\n            $errorMessage = \"Could not $action person. Error: $($ex.ErrorDetails.Message)\"\r\n        }\r\n        else {\r\n            #$errorObj = Resolve-HTTPError -ErrorObject $ex\r\n            $errorMessage = \"Could not $action person. Error: $($ex.Exception.Message)\"\r\n        }\r\n    }\r\n    else {\r\n        $errorMessage = \"Could not $action person. Error: $($ex.Exception.Message) $($ex.ScriptStackTrace)\"\r\n    }\r\n\r\n    # Only log when there are no lookup values, as these generate their own audit message\r\n    Write-Error \"Failed to update attribute [mobileNumber] of Topdesk user [$employeeID] to [$phoneMobile] and/or [phoneNumber] to [$phoneFixed]: Error: $errorMessage\"\r\n    $Log = @{\r\n        Action            = \"UpdateAccount\" # optional. ENUM (undefined = default) \r\n        System            = \"Topdesk\" # optional (free format text) \r\n        Message           = \"Failed to update attribute [mobileNumber] of Topdesk user [$employeeID] to [$phoneMobile] and/or [phoneNumber] to [$phoneFixed]: Error: $errorMessage\" # required (free format text) \r\n        IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n        TargetDisplayName = $displayName # optional (free format text) \r\n        TargetIdentifier  = $([string]$employeeID) # optional (free format text) \r\n    }\r\n    #send result back  \r\n    Write-Information -Tags \"Audit\" -MessageData $log\r\n}\r\n#endregion Topdesk","runInCloud":false}
'@ 

Invoke-HelloIDDelegatedForm -DelegatedFormName $delegatedFormName -DynamicFormGuid $dynamicFormGuid -AccessGroups $delegatedFormAccessGroupGuids -Categories $delegatedFormCategoryGuids -UseFaIcon "True" -FaIcon "fa fa-phone" -task $tmpTask -returnObject ([Ref]$delegatedFormRef) 
<# End: Delegated Form #>

