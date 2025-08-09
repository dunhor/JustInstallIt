
param (
    [Parameter(Mandatory, Position = 0)]
    [string]$AppxPath
)

Add-Type -AssemblyName System.IO.Compression.FileSystem

# Extract the AppxManifest.xml so that we can get the proper subject name needed for the cert
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

# Cert information
$certFriendlyName = "JustInstallIt Signing Cert"
$userStore = "Cert:\CurrentUser\My"

# Check for existing certificate
$cert = Get-ChildItem -Path $userStore | Where-Object { ($_.Subject -eq $appxSubject) -and ($_.FriendlyName -eq $certFriendlyName) }

if (-not $cert) {
    Write-Host "Creating new self-signed certificate: $certFriendlyName"
    $cert = New-SelfSignedCertificate -Type Custom -KeyUsage DigitalSignature -CertStoreLocation $userStore `
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

# By default, try and put the cert in the Local Computer Trusted People store. This requires admin, so fall back to the
# Current User Root store, which seems to sometimes work, though it's unclear when or why
$compTrustStore = "Cert:\LocalMachine\TrustedPeople"
$userTrustStore = "Cert:\CurrentUser\Root"

# Check to see if the cert is already in the Computer's store
$compCert = Get-ChildItem "$compTrustStore\$($cert.Thumbprint)" -ErrorAction SilentlyContinue
if (-not $compCert) {
    try {
        Write-Host "Importing certificate to the Local Computer's Trusted People store..."
        Import-PfxCertificate -FilePath $pfxPath -CertStoreLocation $compTrustStore -Password $securePfxPassword -ErrorAction Stop | Out-Null
        Write-Host "Import successful"
    } catch {
        Write-Warning "Import into the Local Computer's Trusted People store failed."
        Write-Warning "NOTE: If the package is not installable after this step, you may need to re-run this script as admin or install the certificate manually."
        $userCert = Get-ChildItem "$userTrustStore\$($cert.Thumbprint)" -ErrorAction SilentlyContinue
        if (-not $userCert) {
            Write-Host "Falling back to Current User's Root store..."
            Import-PfxCertificate -FilePath $pfxPath -CertStoreLocation $userTrustStore -Password $securePfxPassword | Out-Null
        }
    }
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
