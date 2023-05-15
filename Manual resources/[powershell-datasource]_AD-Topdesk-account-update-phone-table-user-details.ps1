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
