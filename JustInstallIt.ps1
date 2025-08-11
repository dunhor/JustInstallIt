
param (
    [Parameter(Mandatory, Position = 0)]
    [string]$AppxPath,

    [Parameter(Mandatory = $false)]
    [bool]$CreateInUserStore = $false,

    [Parameter(Mandatory = $false)]
    [bool]$InstallInUserStore = $false
)

# Determine if we're running as admin. This will affect where the certificate is installed, unless told otherwise
$runningAsAdmin = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $runningAsAdmin) {
    # If not running as admin, create in user store, even if caller explicitly said not to
    $CreateInUserStore = $true
}

if (-not $PSBoundParameters.ContainsKey("InstallInUserStore")) {
    $InstallInUserStore = $CreateInUserStore
}

# Extract the AppxManifest.xml so that we can get the proper subject name needed for the cert
Add-Type -AssemblyName System.IO.Compression.FileSystem

$absPath = Resolve-Path $AppxPath # OpenRead can fail if given a relative path
$appxContents = [System.IO.Compression.ZipFile]::OpenRead($absPath)
$entry = $appxContents.Entries | Where-Object { $_.FullName -eq "AppxManifest.xml" }

$manifestPath = [System.IO.Path]::GetTempFileName() + ".xml"
[System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $manifestPath)

$manifestData = [xml](Get-Content -Path $manifestPath)
$appxSubject = $manifestData.Package.Identity.Publisher
Write-Host "Package has publisher: $appxSubject"

# We have the subject name; cleanup
Remove-Item $manifestPath
$appxContents.Dispose()

# Cert information. If we're running as admin, prefer to locate/create the cert in the LocalMachine store, unless explicitly
# told by the user to use the CurrentUser store. This is somewhat of a security thing; we want to restrict access to the
# private key, so not just any medium IL application can use it.
$certFriendlyName = "JustInstallIt Package Signing Cert"
$certCreateStore = if ($CreateInUserStore) { "Cert:\CurrentUser\My" } else { "Cert:\LocalMachine\My" }
$certInstallStore = if ($InstallInUserStore) { "Cert:\CurrentUser\Root" } else { "Cert:\LocalMachine\TrustedPeople" }

# Check for existing certificate
$cert = Get-ChildItem -Path $certCreateStore | Where-Object { ($_.Subject -eq $appxSubject) -and ($_.FriendlyName -eq $certFriendlyName) }

if (-not $cert) {
    Write-Host "Creating new self-signed certificate: $certFriendlyName"
    $cert = New-SelfSignedCertificate -Type Custom -KeyUsage DigitalSignature -CertStoreLocation $certCreateStore `
        -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3", "2.5.29.19={text}") -Subject $appxSubject `
        -FriendlyName $certFriendlyName
}
else {
    Write-Host "Using existing certificate: $certFriendlyName"
}

# Generate a random password for the PFX file
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$bytes = New-Object byte[] 16
$rng.GetBytes($bytes)
$pfxPassword = [Convert]::ToBase64String($bytes)
$securePfxPassword = ConvertTo-SecureString -String $pfxPassword -Force -AsPlainText

# Export certificate to a temporary PFX file (required for signtool)
$pfxPath = [System.IO.Path]::GetTempFileName() + ".pfx"
Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $securePfxPassword | Out-Null

# Install the cert if it hasn't been installed yet
$compCert = Get-ChildItem "$certInstallStore\$($cert.Thumbprint)" -ErrorAction SilentlyContinue
if (-not $compCert) {
    Write-Host "Importing certificate to $certInstallStore..."

    # NOTE: For some reason, installing into the user's Root store seems to _never_ work, however installing to the user's
    # root store appears to _sometimes_ work. It's not clear under which circumstances this will work, so warn the user
    # that they may need to run as admin
    if ($InstallInUserStore) {
        Write-Warning "Installing the certificate to the user's Root store may or may not work"
        if ($runningAsAdmin) {
            Write-Warning "If the application fails to install, try running without 'InstallInUserStore'"
        } else {
            Write-Warning "If the application fails to install, try running as admin"
        }
    }

    Import-PfxCertificate -FilePath $pfxPath -CertStoreLocation $certInstallStore -Password $securePfxPassword -ErrorAction Stop | Out-Null
    Write-Host "Import successful"
}

# Find signtool.exe (assumes Windows SDK is installed and in PATH)
$signtool = "signtool.exe"
if (-not (Get-Command $signtool -ErrorAction SilentlyContinue)) {
    throw "signtool.exe not found in PATH. Please install the Windows SDK."
}

# Sign the package with the new cert
& $signtool sign /fd SHA256 /a /f $pfxPath /p $pfxPassword $AppxPath

# Clean up temporary PFX file
Remove-Item $pfxPath -Force

Add-AppxPackage $AppxPath
