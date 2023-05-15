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

        Write-Information "Successfully queried data. Result count: $(($users | Measure-Object).Count)"

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
