#######################################################################
# Template: RHo HelloID SA Delegated form task
# Name:     AD-Topdesk-account-update-phone
# Date:     15-05-2023
#######################################################################

# For basic information about delegated form tasks see:
# https://docs.helloid.com/en/service-automation/delegated-forms/delegated-form-powershell-scripts/add-a-powershell-script-to-a-delegated-form.html

# Service automation variables:
# https://docs.helloid.com/en/service-automation/service-automation-variables/service-automation-variable-reference.html

#region init
# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# global variables (Automation --> Variable libary):
# $globalVar = $globalVarName

# variables configured in form:
$userPrincipalName = $form.gridUsers.UserPrincipalName
$phoneMobile = $form.mobilePhone
$phoneFixed = $form.officePhone
$employeeID = $form.gridUsers.employeeID
$displayName = $form.gridUsers.displayName
#endregion init

#region global functions
function Resolve-HTTPError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            ValueFromPipeline
        )]
        [object]$ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            FullyQualifiedErrorId = $ErrorObject.FullyQualifiedErrorId
            MyCommand             = $ErrorObject.InvocationInfo.MyCommand
            RequestUri            = $ErrorObject.TargetObject.RequestUri
            ScriptStackTrace      = $ErrorObject.ScriptStackTrace
            ErrorMessage          = ''
        }
        if ($ErrorObject.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') {
            $httpErrorObj.ErrorMessage = $ErrorObject.ErrorDetails.Message
        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            $httpErrorObj.ErrorMessage = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
        }
        Write-Output $httpErrorObj
    }
}
#endregion global functions

#region AD
try {
    Write-Information "Querying AD user [$userPrincipalName]"
    $adUser = Get-ADuser -Filter { UserPrincipalName -eq $userPrincipalName } 
    Write-Information "Found AD user [$userPrincipalName]"
}
catch {
    Write-Error "Could not find AD user [$userPrincipalName]. Error: $($_.Exception.Message)"    
    $Log = @{
        Action            = "UpdateAccount" # optional. ENUM (undefined = default) 
        System            = "ActiveDirectory" # optional (free format text) 
        Message           = "Could not find AD user [$userPrincipalName]. Error: $($_.Exception.Message)" # required (free format text) 
        IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
        TargetDisplayName = $displayName # optional (free format text) 
        TargetIdentifier  = $([string]$adUser.SID) # optional (free format text) 
    }
    #send result back  
    Write-Information -Tags "Audit" -MessageData $log  
}
try {
    Write-Information "Start updating AD user [$userPrincipalName]"
    if ([String]::IsNullOrEmpty($phoneMobile) -eq $true) {
        Set-ADUser -Identity $adUSer -MobilePhone $null
    }
    else {
        Set-ADUser -Identity $adUSer -MobilePhone $phoneMobile
    }

    if ([String]::IsNullOrEmpty($phoneFixed) -eq $true) {
        Set-ADUser -Identity $adUSer -OfficePhone $null
    }
    else {
        Set-ADUser -Identity $adUSer -OfficePhone $phoneFixed
    }
    
    Write-Information "Finished update attribute [phoneMobile] of AD user [$userPrincipalName] to [$phoneMobile] and/or [officePhone] to [$phoneFixed]"
    $Log = @{
        Action            = "UpdateAccount" # optional. ENUM (undefined = default) 
        System            = "ActiveDirectory" # optional (free format text) 
        Message           = "Successfully updated attribute [phoneMobile] of AD user [$userPrincipalName] to [$phoneMobile] and/or [officePhone] to [$phoneFixed]" # required (free format text) 
        IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
        TargetDisplayName = $adUser.name # optional (free format text) 
        TargetIdentifier  = $([string]$adUser.SID) # optional (free format text) 
    }
    #send result back  
    Write-Information -Tags "Audit" -MessageData $log    
}
catch {
    Write-Error "Could not update attribute [phoneMobile] of AD user [$userPrincipalName] to [$phoneMobile] and/or [officePhone] to [$phoneFixed]. Error: $($_.Exception.Message)"
    $Log = @{
        Action            = "UpdateAccount" # optional. ENUM (undefined = default) 
        System            = "ActiveDirectory" # optional (free format text) 
        Message           = "Failed to update attribute [phoneMobile] of AD user [$userPrincipalName] to [$phoneMobile] and/or [officePhone] to [$phoneFixed]" # required (free format text) 
        IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
        TargetDisplayName = $adUser.name # optional (free format text) 
        TargetIdentifier  = $([string]$adUser.SID) # optional (free format text) 
    }
    #send result back  
    Write-Information -Tags "Audit" -MessageData $log      
}
#endregion AD

#region Topdesk
function Set-AuthorizationHeaders {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Username,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $ApiKey
    )
    # Create basic authentication string
    $bytes = [System.Text.Encoding]::ASCII.GetBytes("${Username}:${Apikey}")
    $base64 = [System.Convert]::ToBase64String($bytes)

    # Set authentication headers
    $authHeaders = [System.Collections.Generic.Dictionary[string, string]]::new()
    $authHeaders.Add("Authorization", "BASIC $base64")
    $authHeaders.Add("Accept", 'application/json')

    Write-Output $authHeaders
}

function Invoke-TopdeskRestMethod {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Method,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Uri,

        [object]
        $Body,

        [string]
        $ContentType = 'application/json; charset=utf-8',

        [Parameter(Mandatory)]
        [System.Collections.IDictionary]
        $Headers
    )
    process {
        try {
            $splatParams = @{
                Uri         = $Uri
                Headers     = $Headers
                Method      = $Method
                ContentType = $ContentType
            }
            if ($Body) {
                $splatParams['Body'] = [Text.Encoding]::UTF8.GetBytes($Body)
            }
            Invoke-RestMethod @splatParams -Verbose:$false
        }
        catch {
            $PSCmdlet.ThrowTerminatingError($_)
        }
    }
}

function Get-TopdeskPersonByCorrelationAttribute {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $BaseUrl,

        [Parameter(Mandatory)]
        [System.Collections.IDictionary]
        $Headers,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Object]
        $Account,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String]
        $CorrelationAttribute
    )

    # Check if the correlation attribute exists in the account object set in the mapping
    if (-not([bool]$account.PSObject.Properties[$CorrelationAttribute])) {
        $errorMessage = "The correlation attribute [$CorrelationAttribute] is missing in the account mapping. This is a scripting issue."
        throw $errorMessage
    }

    # Check if the correlationAttribute is not empty
    if ([string]::IsNullOrEmpty($account.$CorrelationAttribute)) {
        $errorMessage = "The correlation attribute [$CorrelationAttribute] is empty. This is likely a scripting issue."
        throw $errorMessage
    }

    # Lookup value is filled in, lookup value in Topdesk
    $splatParams = @{
        Uri     = "$baseUrl/tas/api/persons?page_size=2&query=$($correlationAttribute)=='$($account.$CorrelationAttribute)'"
        Method  = 'GET'
        Headers = $Headers
    }
    write-verbose ($splatParams | ConvertTo-Json)
    $responseGet = Invoke-TopdeskRestMethod @splatParams

    # Check if only one result is returned
    if ([string]::IsNullOrEmpty($responseGet.id)) {
        # no results found
        # Multiple records found, correlation
        $errorMessage = "No person found with [$CorrelationAttribute] [$($account.$CorrelationAttribute)]"
        throw $errorMessage
    }
    elseif ($responseGet.Count -eq 1) {
        # one record found, correlate, return user
        write-output $responseGet
    }
    else {
        # Multiple records found, correlation
        $errorMessage = "Multiple [$($responseGet.Count)] persons found with [$CorrelationAttribute] [$($account.$CorrelationAttribute)]. Login names: [$($responseGet.tasLoginName)]"
        throw $errorMessage
    }
}

function Set-TopdeskPerson {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $BaseUrl,

        [Parameter(Mandatory)]
        [System.Collections.IDictionary]
        $Headers,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Object]
        $Account,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Object]
        $TopdeskPerson
    )

    Write-Verbose "Updating person"
    $splatParams = @{
        Uri     = "$BaseUrl/tas/api/persons/id/$($TopdeskPerson.id)"
        Method  = 'PATCH'
        Headers = $Headers
        Body    = $Account | ConvertTo-Json
    }
    # Write-Information ($splatParams | ConvertTo-Json)
    $null = Invoke-TopdeskRestMethod @splatParams
}

try {
    $username = $TopdeskUsername
    $apikey = $TopdeskAPIkey
    $baseUrl = $TopdeskUrl

    # Account mapping. See for all possible options the Topdesk 'supporting files' API documentation at
    # https://developers.topdesk.com/explorer/?page=supporting-files#/Persons/createPerson
    $account = [PSCustomObject]@{
        employeeNumber = $employeeID
        mobileNumber   = $phoneMobile
        phoneNumber    = $phoneFixed
    }

    $correlationAttribute = 'employeeNumber'

    
    $action = 'Process'

    Write-Information "Querying Topdesk person [$employeeID]"

    # Setup authentication headers
    $authHeaders = Set-AuthorizationHeaders -UserName $username -ApiKey $apiKey

    # get person
    $splatParamsPerson = @{
        Account              = $account
        CorrelationAttribute = $correlationAttribute
        Headers              = $authHeaders
        BaseUrl              = $baseUrl
    }
    $TopdeskPerson = Get-TopdeskPersonByCorrelationAttribute @splatParamsPerson

    Write-Information "Found Topdesk person [$employeeID]"

    $action = 'Update'

    Write-Information "Start updating Topdesk person [$employeeID]"

    # Update TOPdesk person
    $splatParamsPersonUpdate = @{
        TopdeskPerson = $TopdeskPerson
        Account       = $account
        Headers       = $authHeaders
        BaseUrl       = $baseUrl
    }
    Set-TopdeskPerson @splatParamsPersonUpdate

    Write-Information "Finished update attribute [mobileNumber] of Topdesk user [$($TopdeskPerson.id)] to [$phoneMobile] and/or [phoneNumber] to [$phoneFixed]"
    $Log = @{
        Action            = "UpdateAccount" # optional. ENUM (undefined = default) 
        System            = "Topdesk" # optional (free format text) 
        Message           = "Successfully updated attribute [mobileNumber] of Topdesk user [$($TopdeskPerson.id)] to [$phoneMobile] and/or [phoneNumber] to [$phoneFixed]" # required (free format text) 
        IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
        TargetDisplayName = $displayName # optional (free format text) 
        TargetIdentifier  = $([string]$TopdeskPerson.id) # optional (free format text) 
    }
    #send result back  
    Write-Information -Tags "Audit" -MessageData $log
}
catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        if (-Not [string]::IsNullOrEmpty($ex.ErrorDetails.Message)) {
            $errorMessage = "Could not $action person. Error: $($ex.ErrorDetails.Message)"
        }
        else {
            #$errorObj = Resolve-HTTPError -ErrorObject $ex
            $errorMessage = "Could not $action person. Error: $($ex.Exception.Message)"
        }
    }
    else {
        $errorMessage = "Could not $action person. Error: $($ex.Exception.Message) $($ex.ScriptStackTrace)"
    }

    # Only log when there are no lookup values, as these generate their own audit message
    Write-Error "Failed to update attribute [mobileNumber] of Topdesk user [$employeeID] to [$phoneMobile] and/or [phoneNumber] to [$phoneFixed]: Error: $errorMessage"
    $Log = @{
        Action            = "UpdateAccount" # optional. ENUM (undefined = default) 
        System            = "Topdesk" # optional (free format text) 
        Message           = "Failed to update attribute [mobileNumber] of Topdesk user [$employeeID] to [$phoneMobile] and/or [phoneNumber] to [$phoneFixed]: Error: $errorMessage" # required (free format text) 
        IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
        TargetDisplayName = $displayName # optional (free format text) 
        TargetIdentifier  = $([string]$employeeID) # optional (free format text) 
    }
    #send result back  
    Write-Information -Tags "Audit" -MessageData $log
}
#endregion Topdesk
