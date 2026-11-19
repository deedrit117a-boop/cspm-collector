# Start the control page (collect web). The password is never stored in this file: it is asked for when MONGO_URI is not set.
#   .\start-web.ps1              default port 8765
#   .\start-web.ps1 -Port 8766   another port
param([int]$Port = 8765, [string]$AwsProfile = "dev-stove-platform")

Set-Location $PSScriptRoot

# host list, user and database are not secret; only the password is asked for
$MongoHosts = "in-house-01-dev.mongodb.sginfra.net:27017,in-house-02-dev.mongodb.sginfra.net:27017,in-house-03-dev.mongodb.sginfra.net:27017"
$MongoUser = "appacl"
$MongoDb = "security_manager_acl"

if (-not $env:MONGO_URI) {
    $secure = Read-Host "MongoDB password of user '$MongoUser' (typing is hidden)" -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try { $password = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    if (-not $password) { Write-Error "The password is empty."; exit 1 }
    $env:MONGO_URI = "mongodb://${MongoUser}:$([uri]::EscapeDataString($password))@$MongoHosts/$MongoDb"
    $password = $null
}

if (-not $env:AWS_PROFILE) { $env:AWS_PROFILE = $AwsProfile }

# corporate TLS-inspection CA bundle (AWS and Akamai calls)
$bundle = Join-Path $env:USERPROFILE ".env-heejim\corp-ca-bundle.pem"
if (Test-Path $bundle) {
    if (-not $env:AWS_CA_BUNDLE)      { $env:AWS_CA_BUNDLE = $bundle }
    if (-not $env:REQUESTS_CA_BUNDLE) { $env:REQUESTS_CA_BUNDLE = $bundle }
    if (-not $env:SSL_CERT_FILE)      { $env:SSL_CERT_FILE = $bundle }
}

$busy = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
if ($busy) { Write-Error "Port $Port is already in use (PID $($busy[0].OwningProcess)). Stop that process or use -Port."; exit 1 }

Write-Host "http://127.0.0.1:$Port  (AWS_PROFILE=$env:AWS_PROFILE)  stop: Ctrl+C"
& "$PSScriptRoot\.venv\Scripts\collect.exe" web --config "$PSScriptRoot\config.yaml" --port $Port
