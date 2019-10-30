## Original script created by Robbie Vance here: http://pleasework.robbievance.net/howto-get-webroot-endpoints-using-unity-rest-api-and-powershell/
## Script altered by Kevin Byrd to provide an additional method of sending/managing Agent Commands and usage reports via Unity API.
## This script requires that Powershell Scripts be enabled to run on the OS, this can often be disabled via GPO.
## Requires .Net Framework 4.5 + \ Powershell 3.0 or newer.
## Windows PowerShell 3.0 requires the full installation of Microsoft .NET Framework 4. Windows 8 and Windows Server 2012 include Microsoft .NET Framework 4.5 by default, which fulfills this requirement.
## THIS IS NOT AN OFFICIAL WEBROOT SCRIPT NOR IS IT SUPPORTED BY WEBROOT
#
Write-Host "Welcome to the Webroot Essentials Utility. Please hold while the minimum version check for .NET and Powershell takes place..." -ForegroundColor Magenta

$versionMinimum = (((Get-ItemProperty "HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full").Release -ge 378389), $PSVersionTable.PSVersion.Major -ile "2")

#Requires -Version 3.0 

Start-Sleep -seconds 2

if ($versionMinimum -ieq "True") {
    Write-Host "Minimum .Net Framework/Powershell version met, continuing..." -ForegroundColor Green
    New-PSDrive -name HKCR -PSProvider registry -Root HKEY_CLASSES_ROOT -ErrorAction SilentlyContinue | ForEach-Object { write-output " " }
    Start-Sleep -Seconds 1
}

Start-Sleep -Seconds 2

write-host "This utility was created to provide an additional method of sending/managing Agent Commands and reports via Unity API" -ForegroundColor Magenta 

Start-Sleep -Seconds 2

write-host "To begin we'll first need to obtain access to the Webroot Unity API" -ForegroundColor Magenta

Start-Sleep -Seconds 2

DO {
    # The base URL for which all REST operations will be performed against
    $BaseURL = 'https://unityapi.webrootcloudav.com'

    # The GSM Parent keycode belonging to your account
    $Keycode = Read-Host -Prompt 'Please enter your Webroot Parent key'

    # Fill for testing purposes - comment out any other time.
    #$Keycode = ''

    Start-Sleep -Seconds 2

    # An administrator user for your Webroot portal -- this is typically the same user you use to login to the main portal
    $WebrootUser = Read-Host -Prompt 'Please enter your Webroot username'

    # Fill for testing purposes - comment out any other time.
    #$WebrootUser = ''

    Start-Sleep -Seconds 2

    # This is typically the same password used to log into the main portal
    $WebrootPassword = Read-Host -Prompt 'Please enter your Webroot password' -AsSecureString

    $WebrootPW = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($WebrootPassword))

    # Fill for testing purposes - comment out any other time.
    #$WebrootPW = ''

    Start-Sleep -Seconds 2

    # This must have previously been generated from the Webroot GSM
    $APIClientID = (Read-Host -Prompt 'Please enter your Webroot Client ID')

    Start-Sleep -Seconds 2

    $APIClientSecret = Read-Host -Prompt 'Please enter your Webroot Client Secret' -AsSecureString

    $APICS = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($APIClientSecret))

    #Fill for testing purposes - comment out any other time.
    #$APIClientID = ''
    #$APICS = ''

    Start-Sleep -Seconds 2

    # You must first get a token which will be good for 300 seconds of future queries.  We do that from here
    $TokenURL = "$BaseURL/auth/token"

    # Once we have the token, we must get the SiteID of the site with the keycode we wish to view Endpoints from
    $SiteIDURL = "$BaseURL/service/api/console/gsm/$KeyCode/sites"

    # All Rest Credentials must be first converted to a base64 string so they can be transmitted in this format
    $Credentials = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($APIClientID + ":" + $APICS ))

    write-host "Obtaining an access token" -ForegroundColor Green

    start-sleep -seconds 2

    $Params = @{
        "ErrorAction"       = "Stop"
        "InformationAction" = "Stop"
        "URI"               = $TokenURL
        "Headers"           = @{"Authorization" = "Basic " + $Credentials }
        "Body"              = @{
            "username"   = $WebrootUser
            "password"   = $WebrootPW
            "grant_type" = 'password'
            "scope"      = '*'
        }
        "Method"            = 'post'
        "ContentType"       = 'application/x-www-form-urlencoded'
    }

    $AccessToken = try { (Invoke-RestMethod @Params).access_token } catch {
        # Dig into the exception to get the Response details.
        # Note that value__ is not a typo.
        Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__
        Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription
    }

    #Enable the option below to blank out the Access Token variable for testing purposes.
    #$AccessToken = ""

    if ($AccessToken -ieq $_.Exception.Response.StatusCode.400) {
        Write-host "Access token not obtained. " -ForegroundColor Red -NoNewline
        Start-Sleep -Seconds 2
        Write-host "Please try to authenticate again." -ForegroundColor Red
        Start-Sleep -Seconds 2
    
    } 
    elseif ($AccessToken -inotlike $null) {
        Write-host "Access token obtained" -ForegroundColor Green
    }
} until ($AccessToken -inotlike $null)

Start-Sleep -Seconds 2

## Adding options starting here

Do {
    Do {
        $UAction = (Read-Host -Prompt "What would you like to do - run an Agent Command, Usage Report, or Change Policy? Type AC, R, CP")
        
        if ($UAction -ieq "CP") {  

            Start-Sleep -Seconds 2

            write-host "Obtaining list of sites belonging to GSM key" -ForegroundColor Green

            $Params = @{
                "InformationAction" = "Stop"
                "URI"               = $SiteIDURL
                "ContentType"       = "application/json"
                "Headers"           = @{"Authorization" = "Bearer " + $AccessToken }
                "Method"            = "Get"
            }

            $SiteID = try { (Invoke-RestMethod @Params).Sites } catch {
                # Dig into the exception to get the Response details.
                # Note that value__ is not a typo.
                Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__
                Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription  
            }

            Start-Sleep -Seconds 2

            if ($SiteID -ieq $_.Exception.Response.StatusCode.400 ) {
                Write-Host "Action Failed. Please try again." -ForegroundColor Red
                Start-Sleep -Seconds 2
            }
            else {

                $SiteID | Format-Table -Property SiteName, SiteID, AccountKeycode

                Start-Sleep -Seconds 2

                # Prompts user to choose a site from the listing
                $SetSite = (Read-Host -Prompt 'Copy/Paste the desired SiteId from the list to continue') 

                # Fill for testing purposes - comment out any other time.
                #$SetSite = ''

                Start-Sleep -Seconds 2

                $EndpointURL = "$BaseURL/service/api/console/gsm/$KeyCode/sites/$SetSite/endpoints?PageSize=1000"

                write-host "Obtaining list of endpoints belonging to selected Site" -ForegroundColor Green

                $Params = @{
                    "InformationAction" = "Stop"
                    "ErrorAction"       = "Stop"
                    "URI"               = $EndpointURL
                    "ContentType"       = "application/json"
                    "Headers"           = @{"Authorization" = "Bearer " + $AccessToken }
                    "Method"            = "Get"
                }

                $AllEndpoints = try { Invoke-RestMethod @Params } catch {
                    # Dig into the exception to get the Response details.
                    # Note that value__ is not a typo.
                    Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__
                    Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription
                    start-sleep -seconds 2                
                }

                if ($AllEndpoints -ieq $_.Exception.Response.StatusCode.400 ) {
                    Write-Host "Action Failed. Please try again." -ForegroundColor Red
                    Start-Sleep -Seconds 2
                }
                else {

                    Start-Sleep -Seconds 2

                    $AllEndpoints.Endpoints | Format-Table -Property HostName, EndpointId, LastSeen

                    Start-Sleep -Seconds 2

                    # Prompts user to copy/paste the desired endpoint(s)
                    $ChosenAgents = Read-Host -Prompt 'Copy/Paste the desired EndpointId from the list to continue, use a comma to add more than one' 

                    # Filled for testing purposes - comment out any other time.
                    #$ChosenAgents = ''

                    Start-Sleep -Seconds 2

                    Write-Host "Obtaining list of policies." -ForegroundColor Green

                    $PolicyL = Write-Output (Invoke-RestMethod -Uri "https://unityapi.webrootcloudav.com/service/api/console/gsm/$Keycode/sites/$SetSite/policies" -Method Get -ContentType 'application/json' -Headers @{"Authorization" = "Bearer " + $AccessToken })
            
                    $PolicyL.policies | Format-table -Property PolicyName, PolicyID, LivePolicy, GlobalPolicy, DateCreated
            
                    Start-Sleep -Seconds 2
            
                    # Prompts user to copy/paste desired Policy
                    $CPolicy = (read-Host "Copy/Paste the desired PolicyId from the list to continue.")

                    Start-Sleep -Seconds 2

                    $Params = @{
                        "PolicyId"      = "$CPolicy"
                        "EndpointsList" = "$ChosenAgents"
                        "ErrorAction"   = "Stop"
                    }

                    $Body = ($Params | ConvertTo-Json)

                    Invoke-RestMethod -Uri "https://unityapi.webrootcloudav.com/service/api/console/gsm/$Keycode/sites/$SetSite/endpoints/policy" -Method Put -Body "$Body" -ContentType 'application/json' -Headers @{"Authorization" = "Bearer " + $AccessToken }

                    Start-Sleep -Seconds 2

                    write-host "Policy Change Command has been sent" -ForegroundColor Green

                    Start-Sleep -Seconds 2

                }                       
            }
        }

        elseif ($UAction -ieq "AC") {
                                      
            Start-Sleep -Seconds 2

            write-host "Obtaining list of sites belonging to GSM key" -ForegroundColor Green

            $Params = @{
                "InformationAction" = "Stop"
                "URI"               = $SiteIDURL
                "ContentType"       = "application/json"
                "Headers"           = @{"Authorization" = "Bearer " + $AccessToken }
                "Method"            = "Get"
            }

            $SiteID = try { (Invoke-RestMethod @Params).Sites } catch {
                # Dig into the exception to get the Response details.
                # Note that value__ is not a typo.
                Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ 
                Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription
                start-sleep -seconds 2   
            }

            if ($SiteID -ieq $_.Exception.Response.StatusCode.400 ) {
                Write-Host "Action Failed. Please try again." -ForegroundColor Red
                Start-Sleep -Seconds 2
            }
            else {

                Start-Sleep -Seconds 2

                $SiteID | Format-Table -Property SiteName, SiteID, AccountKeycode

                Start-Sleep -Seconds 2

                # Prompts user to choose a site from the listing
                $SetSite = (Read-Host -Prompt 'Copy/Paste the desired SiteId from the list to continue') 

                # Fill for testing purposes - comment out any other time.
                #$SetSite = ''

                Start-Sleep -Seconds 2

                $EndpointURL = "$BaseURL/service/api/console/gsm/$KeyCode/sites/$SetSite/endpoints?PageSize=1000"

                write-host "Obtaining list of endpoints belonging to selected Site" -ForegroundColor Green

                $Params = @{
                    "InformationAction" = "Stop"
                    "ErrorAction"       = "Stop"
                    "URI"               = $EndpointURL
                    "ContentType"       = "application/json"
                    "Headers"           = @{"Authorization" = "Bearer " + $AccessToken }
                    "Method"            = "Get"
                }

                $AllEndpoints = try { Invoke-RestMethod @Params } catch {
                    # Dig into the exception to get the Response details.
                    # Note that value__ is not a typo.
                    Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ 
                    Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription
                }

                if ($AllEndpoints -ieq $_.Exception.Response.StatusCode.400 ) {
                    Write-Host "Action Failed. Please try again." -ForegroundColor Red
                    Start-Sleep -Seconds 2
                }
                else {

                    Start-Sleep -Seconds 2

                    $AllEndpoints.Endpoints | Format-Table -Property HostName, EndpointId, LastSeen

                    Start-Sleep -Seconds 2

                    # Prompts user to copy/paste the desired endpoint(s)
                    $ChosenAgents = Read-Host -Prompt 'Copy/Paste the desired EndpointId from the list to continue, use a comma to add more than one' 

                    # Fill for testing purposes - comment out any other time.
                    #$ChosenAgents = ''

                    Start-Sleep -Seconds 2

                    Do { 
                        #Prompts user to type out the agent command they desire to send
                        $ACommand = Read-Host -Prompt 'Type the desired agent command from the list to continue; scan, cleanup, uninstall, changekeycode, restart'

                        if ($ACommand -inotin "scan", "cleanup", "uninstall", "changekeycode", "restart") { 
                            Start-Sleep -Seconds 2
                            write-host "Input received is not a valid option, please try again." -ForegroundColor Red
                            Start-Sleep -Seconds 2
                        }
                        else {
                            continue
                        }
                    }
                    until ($ACommand -iin "scan", "cleanup", "uninstall", "changekeycode", "restart")

                    # Prompts user for keycode when sending Change Keycode agent command
                    if ( $ACommand -ieq "changekeycode") {
                        Read-Host -Prompt 'Please type the desired keycode' | Set-Variable -Name CKeyCode
                    } 
                    else {
                        Set-Variable -Name CKeyCode -Value ""
                    }
         
                    # Filled for testing purposes - comment out any other time.
                    #$ACommand = ''

                    Start-sleep -Seconds 2

                    $Params = @{
                        "Command"           = "$ACommand"
                        "EndpointsList"     = "$ChosenAgents"
                        "Parameters"        = "$CKeycode"
                        "InformationAction" = "Stop"
                    }

                    $Body = ($Params | ConvertTo-Json)

                    Invoke-RestMethod -Uri "https://unityapi.webrootcloudav.com/service/api/console/gsm/$Keycode/sites/$SetSite/endpoints/commands" -Method Post -Body "$Body" -ContentType 'application/json' -Headers @{"Authorization" = "Bearer " + $AccessToken }

                    Start-Sleep -Seconds 2

                    write-host "Agent Command has been sent" -ForegroundColor Green

                    Start-Sleep -Seconds 2

                    write-host "Obtaining list Agent Commands that have been sent." -ForegroundColor Green -NoNewline

                    write-host "  CommandState: 1 - Elapsed, 2 - Not Yet Received, 3 - Executed, 4 - Scheduled " -ForegroundColor Red

                    Start-Sleep -Seconds 2

                    $GetList = "$BaseURL/service/api/console/gsm/$KeyCode/sites/$SetSite/commands?pagesize=1000"

                    $Params = @{
                        "InformationAction" = "Stop"
                        "URI"               = $GetList
                        "ContentType"       = "application/json"
                        "Headers"           = @{"Authorization" = "Bearer " + $AccessToken }
                        "Method"            = "Get"
                    }

                    $ACommandStatus = try { (Invoke-RestMethod @Params) } catch {
                        # Dig into the exception to get the Response details.
                        # Note that value__ is not a typo.
                        Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ 
                        Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription
                    }

                    if ($ACommandStatus -ieq $_.Exception.Response.StatusCode.400 ) {
                        Write-Host "Action Failed. Please try again." -ForegroundColor Red
                        Start-Sleep -Seconds 2
                    }
                    else {

                        $ACommandStatus.Commands | Format-List -Property HostName, EndpointId, Command, DateRequested, Parameters, CommandState  

                        Start-Sleep -Seconds 10
                    }

                }
            }
        }
        elseif ($UAction -ieq "R") { 

            Start-Sleep -Seconds 2

            write-host "Obtaining list of sites belonging to GSM key" -ForegroundColor Green

            $Params = @{
                "InformationAction" = "Stop"
                "URI"               = $SiteIDURL
                "ContentType"       = "application/json"
                "Headers"           = @{"Authorization" = "Bearer " + $AccessToken }
                "Method"            = "Get"
            }

            $SiteID = try { (Invoke-RestMethod @Params).Sites } catch {
                # Dig into the exception to get the Response details.
                # Note that value__ is not a typo.
                Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ 
                Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription
            }

            Start-Sleep -Seconds 2

            if ($SiteID -ieq $_.Exception.Response.StatusCode.400 ) {
                Write-Host "Action Failed. Please try again." -ForegroundColor Red
                Start-Sleep -Seconds 2
            }
            else {

                $SiteID | Format-Table -Property SiteName, SiteID, AccountKeycode

                Start-Sleep -Seconds 2

                # Prompts user to choose a site from the listing
                $SetSite = (Read-Host -Prompt 'Copy/Paste the desired Site Keycode from the list to continue')

                # Filled for testing purposes - comment out any other time.
                #$SetSite = ''

                Start-Sleep -Seconds 2

                DO {
                    $reportSelection = Read-Host -Prompt "What type of Usage Report would you like? Endpoint, DNS Protection, or WSAT - Type EP, DNSP, WSAT"

                    Start-Sleep -Seconds 2

                    if ($reportSelection -inotin "EP", "DNSP", "WSAT") {
                 
                        write-host "Input received is not a valid option, please try again." -ForegroundColor Red
                    }  
                        
                    else {
                        continue
                    }

                } until ($reportSelection -iin "EP", "DNSP", "WSAT")

                if ($reportSelection -ieq "EP") {

                    Do {
                        $reportLevel = Read-Host -Prompt 'Which report type do you desire? GSM-level summary or Site-level summary - Type GSM or Site'

                        Start-Sleep -Seconds 2

                        if ($reportLevel -inotin "GSM", "Site") {
                 
                            write-host "Input received is not a valid option, please try again." -ForegroundColor Red
                        }  
                        else {
                            continue
                        }
                    }
                    until ($reportLevel -iin "GSM", "Site")

                    if ($reportLevel -ieq "Site") {

                        Do {

                            $reportType = Read-Host -Prompt 'Please type which report type you desire: ActiveEndpoints, ActiveEndpointsWithoutHidden, EndpointsSeenInLast30Days'

                            Start-Sleep -Seconds 2

                            if ($reportType -inotin "ActiveEndpoints", "ActiveEndpointsWithoutHidden", "EndpointsSeenInLast30Days") {
                 
                                write-host "Input received is not a valid option, please try again." -ForegroundColor Red
                            }  
                        
                            else {
                                continue
                            }
                        }

                        until ($reportType -iin "ActiveEndpoints", "ActiveEndpointsWithoutHidden", "EndpointsSeenInLast30Days")

                        $effectiveDate = (Read-Host -Prompt 'Please type the date the report should refer to, eg. 2019-08-16T00:00:00Z')

                        Start-Sleep -Seconds 2

                        $ReportURL = "$BaseURL/service/api/status/reporting/gsm/$KeyCode/sites/$SetSite/endpoints?reportType=$reportType&effectiveDate=$effectiveDate"

                        Start-Sleep -Seconds 2

                        $Params = @{
                            "InformationAction" = "Stop"
                            "URI"               = $ReportURL
                            "ContentType"       = "application/json"
                            "Headers"           = @{"Authorization" = "Bearer " + $AccessToken }
                            "Method"            = "Get"
                        }

                        $FReport = try { (Invoke-RestMethod @Params) } catch {
                            # Dig into the exception to get the Response details.
                            # Note that value__ is not a typo.
                            Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ 
                            Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription   
                        }

                        if ($FReport -ieq $_.Exception.Response.StatusCode.400 ) {
                            Write-Host "Action Failed. Please try again." -ForegroundColor Red
                            Start-Sleep -Seconds 2
                        }
                        else {

                            Write-host "Obtaining Report information" -ForegroundColor Green

                            $FReport | Format-table -Autosize -Wrap

                            start-sleep -seconds 10

                        }
                    }

                    else {
                
                        Do {

                            $reportType = Read-Host -Prompt 'Please type which report type you desire: ActiveEndpoints, ActiveEndpointsWithoutHidden, EndpointsSeenInLast30Days'

                            Start-Sleep -Seconds 2

                            if ($reportType -inotin "ActiveEndpoints", "ActiveEndpointsWithoutHidden", "EndpointsSeenInLast30Days") {
                 
                                write-host "Input received is not a valid option, please try again." -ForegroundColor Red
                            }  
                        
                            else {
                                continue
                            }
                        }

                        until ($reportType -iin "ActiveEndpoints", "ActiveEndpointsWithoutHidden", "EndpointsSeenInLast30Days")

                        $effectiveDate = (Read-Host -Prompt 'Please type the date the report should refer to, eg. 2019-08-16T00:00:00Z')

                        Start-Sleep -Seconds 2

                        $ReportURL = "$BaseURL/service/api/status/reporting/gsm/$KeyCode/endpoints?reportType=$reportType&effectiveDate=$effectiveDate"

                        Start-Sleep -Seconds 2

                        $Params = @{
                            "InformationAction" = "Stop"
                            "URI"               = $ReportURL
                            "ContentType"       = "application/json"
                            "Headers"           = @{"Authorization" = "Bearer " + $AccessToken }
                            "Method"            = "Get"
                        }

                        $FReport = try { (Invoke-RestMethod @Params) } catch {
                            # Dig into the exception to get the Response details.
                            # Note that value__ is not a typo.
                            Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ 
                            Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription   
                        }
    
                        if ($FReport -ieq $_.Exception.Response.StatusCode.400 ) {
                            Write-Host "Action Failed. Please try again." -ForegroundColor Red
                            Start-Sleep -Seconds 2
                        }
                        else {

                            Write-host "Obtaining Report information" -ForegroundColor Green

                            $FReport | Format-table -Autosize -Wrap

                            start-sleep -seconds 10

                        }
                    }            
                }
                elseif ($reportSelection -ieq "DNSP") {
                    Do {
                        $reportLevel = Read-Host -Prompt 'Which report type do you desire? GSM-level summary or Site-level summary - Type GSM or Site'

                        Start-Sleep -Seconds 2

                        if ($reportLevel -inotin "GSM", "Site") {
                 
                            write-host "Input received is not a valid option, please try again." -ForegroundColor Red
                        }  
                        
                        else {
                            continue
                        }
                    }

                    until ($reportLevel -iin "GSM", "Site")

                    Start-Sleep -Seconds 2

                    if ($reportLevel -ieq "GSM") {

                        $reportType = Read-Host -Prompt "Please type which report type you desire: DevicesSeen or DevicesSeenInLast30Days"

                        Start-Sleep -Seconds 2

                        $effectiveDate = (Read-Host -Prompt 'Please type the date the report should refer to, eg. 2019-08-16T00:00:00Z')

                        Start-Sleep -Seconds 2

                        $ReportURL = "$BaseURL/service/api/status/reporting/gsm/$KeyCode/dnsp?reportType=$reportType&effectiveDate=$effectiveDate"

                        Start-Sleep -Seconds 2

                        $Params = @{
                            "InformationAction" = "Stop"
                            "URI"               = $ReportURL
                            "ContentType"       = "application/json"
                            "Headers"           = @{"Authorization" = "Bearer " + $AccessToken }
                            "Method"            = "Get"
                        }

                        $FReport = try { (Invoke-RestMethod @Params) } catch {
                            # Dig into the exception to get the Response details.
                            # Note that value__ is not a typo.
                            Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ 
                            Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription   
                        }
    
                        if ($FReport -ieq $_.Exception.Response.StatusCode.400 ) {
                            Write-Host "Action Failed. Please try again." -ForegroundColor Red
                            Start-Sleep -Seconds 2
                        }
                        else {

                            Write-host "Obtaining Report information" -ForegroundColor Green

                            $FReport | Format-table -Autosize -Wrap

                            start-sleep -seconds 10

                        }
                    }
                    else {
                        $reportType = Read-Host -Prompt "Please type which report type you desire: DevicesSeen or DevicesSeenInLast30Days"

                        Start-Sleep -Seconds 2

                        $effectiveDate = (Read-Host -Prompt 'Please type the date the report should refer to, eg. 2019-08-16T00:00:00Z')

                        Start-Sleep -Seconds 2

                        $ReportURL = "$BaseURL/service/api/status/reporting/gsm/$KeyCode/sites/dnsp?reportType=$reportType&effectiveDate=$effectiveDate"

                        Start-Sleep -Seconds 2

                        $Params = @{
                            "InformationAction" = "Stop"
                            "URI"               = $ReportURL
                            "ContentType"       = "application/json"
                            "Headers"           = @{"Authorization" = "Bearer " + $AccessToken }
                            "Method"            = "Get"
                        }

                        $FReport = try { (Invoke-RestMethod @Params) } catch {
                            # Dig into the exception to get the Response details.
                            # Note that value__ is not a typo.
                            Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ 
                            Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription   
                        }
    
                        if ($FReport -ieq $_.Exception.Response.StatusCode.400 ) {
                            Write-Host "Action Failed. Please try again." -ForegroundColor Red
                            Start-Sleep -Seconds 2
                        }
                        else {

                            Write-host "Obtaining Report information" -ForegroundColor Green

                            $FReport | Format-table -Autosize -Wrap

                            start-sleep -seconds 10

                        }
                    }
                }

                elseif ($reportSelection -ieq "WSAT") {

                    Do {
                        $reportLevel = Read-Host -Prompt 'Which report type do you desire? GSM-level summary or Site-level summary - Type GSM or Site'

                        Start-Sleep -Seconds 2

                        if ($reportLevel -inotin "GSM", "Site") {
                 
                            write-host "Input received is not a valid option, please try again." -ForegroundColor Red
                        }  
                        
                        else {
                            continue
                        }
                    }

                    until ($reportLevel -iin "GSM", "Site")

                    Start-Sleep -Seconds 2

                    if ($reportLevel -ieq "GSM") {

                        $reportType = Read-Host -Prompt "Please type which report type you desire: UsersSeen or UsersSeenInLast30Days"

                        Start-Sleep -Seconds 2

                        $effectiveDate = (Read-Host -Prompt 'Please type the date the report should refer to, eg. 2019-08-16T00:00:00Z')

                        Start-Sleep -Seconds 2

                        $ReportURL = "$BaseURL/service/api/status/reporting/gsm/$KeyCode/wsat?reportType=$reportType&effectiveDate=$effectiveDate"

                        Start-Sleep -Seconds 2

                        $Params = @{
                            "InformationAction" = "Stop"
                            "URI"               = $ReportURL
                            "ContentType"       = "application/json"
                            "Headers"           = @{"Authorization" = "Bearer " + $AccessToken }
                            "Method"            = "Get"
                        }

                        $FReport = try { (Invoke-RestMethod @Params) } catch {
                            # Dig into the exception to get the Response details.
                            # Note that value__ is not a typo.
                            Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ 
                            Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription   
                        }
    
                        if ($FReport -ieq $_.Exception.Response.StatusCode.400 ) {
                            Write-Host "Action Failed. Please try again." -ForegroundColor Red
                            Start-Sleep -Seconds 2
                        }
                        else {

                            Write-host "Obtaining Report information" -ForegroundColor Green

                            $FReport | Format-table -Autosize -Wrap

                            start-sleep -seconds 10

                        }
                    }
                    else {
                        $reportType = Read-Host -Prompt "Please type which report type you desire: UsersSeen or UsersSeenInLast30Days"

                        Start-Sleep -Seconds 2

                        $effectiveDate = (Read-Host -Prompt 'Please type the date the report should refer to, eg. 2019-08-16T00:00:00Z')

                        Start-Sleep -Seconds 2

                        $ReportURL = "$BaseURL/service/api/status/reporting/gsm/$KeyCode/sites/wsat?reportType=$reportType&effectiveDate=$effectiveDate"

                        Start-Sleep -Seconds 2

                        $Params = @{
                            "InformationAction" = "Stop"
                            "URI"               = $ReportURL
                            "ContentType"       = "application/json"
                            "Headers"           = @{"Authorization" = "Bearer " + $AccessToken }
                            "Method"            = "Get"
                        }

                        $FReport = try { (Invoke-RestMethod @Params) } catch {
                            # Dig into the exception to get the Response details.
                            # Note that value__ is not a typo.
                            Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ 
                            Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription   
                        }
    
                        if ($FReport -ieq $_.Exception.Response.StatusCode.400 ) {
                            Write-Host "Action Failed. Please try again." -ForegroundColor Red
                            Start-Sleep -Seconds 2
                        }
                        else {

                            Write-host "Obtaining Report information" -ForegroundColor Green

                            $FReport | Format-table -Autosize -Wrap

                            start-sleep -seconds 10

                        }
                    }
                }

                elseif ($UAction -ine "AC", "R", "CP") {
                    Start-Sleep -Seconds 2
                    write-host "Input received is not a valid option, please try again." -ForegroundColor Red
                    Start-Sleep -Seconds 2
                }
            }
        }
        elseif ($UAction -inotin "AC", "R", "CP") {
            Start-Sleep -Seconds 2
            Write-Host "Invalid option, please check for typos and try again." -ForegroundColor Red
            Start-Sleep -Seconds 2
        }
    }

    until ($UAction -iin "AC", "R", "CP")
                   
    $UAnswer = (read-Host -Prompt "Are you done? Type Y or N")

    Start-Sleep -Seconds 2
}

Until ($UAnswer -ieq 'Y')

Start-Sleep -Seconds 2

Write-Host "Closing utility..." -ForegroundColor Yellow

Start-Sleep -Seconds 3

Exit 