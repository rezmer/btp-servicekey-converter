<#
.SYNOPSIS
    Creates a PKCS#12 (.pfx) file AND a plain PEM bundle from an x509 certificate
    and its RSA private key (e.g. from a SAP BTP service key JSON with
    "uaa.certificate" / "uaa.key") - no OpenSSL required.

.DESCRIPTION
    Compatible with Windows PowerShell 5.1 (.NET Framework 4.7.2+ / 4.8, Windows 11).
    RSA keys only, PKCS#1 ("BEGIN RSA PRIVATE KEY") and PKCS#8 ("BEGIN PRIVATE KEY").

    Private key import uses .NET's native RSA.ImportRSAPrivateKey() /
    ImportPkcs8PrivateKey() when available (.NET Framework 4.8+). If those
    methods are missing (older .NET Framework) or fail for any reason, the
    script automatically falls back to a built-in, minimal ASN.1/DER parser
    that decodes the key by hand - so it keeps working even without 4.8.

    Before exporting, the script verifies that the private key actually
    matches the certificate's public key (modulus comparison) and aborts
    with a clear error if they don't - this catches accidentally mixed-up
    certificate/key pairs early.

    Input options:
      1. File path to a service key JSON (e.g. "uaa.certificate" / "uaa.key")
      2. Paste the JSON directly into the console
      3. Separate file paths to a certificate (.crt/.pem, chain allowed)
         and a key file (.key/.pem)

    Output:
      - A password-protected .pfx (random password generated, or your own
        with confirmation, or supplied via -Password for automation)
      - A plain, unencrypted .pem bundle (same base name, .pem extension)
        containing the certificate chain + private key with real line
        breaks - for tools/portals that need PEM instead of PFX/JSON
        (handle it like the private key it contains)

.PARAMETER ServiceKeyPath
    Optional. Path to the service key JSON file. If omitted, you'll be prompted
    to choose an input method interactively.

.PARAMETER OutputPath
    Optional. Target path for the .pfx file. The .pem file is written next to
    it with the same base name. If omitted, you'll be prompted (default
    suggestion: the folder the script is running from, e.g.
    <script folder>\<date-time>.pfx).

.PARAMETER JsonKeyPath
    Name of the node in the JSON under which 'certificate' and 'key' live.
    For SAP BTP service keys usually "uaa" (default). Only relevant for the
    JSON file/paste input modes.

.PARAMETER Password
    Optional password as SecureString for the PFX. If omitted, you'll be
    asked interactively whether to auto-generate one or set your own
    (with confirmation).

.EXAMPLE
    .\New-PfxFromServiceKey.ps1
    (fully interactive: asks for input method, validates, asks for output path)

.EXAMPLE
    .\New-PfxFromServiceKey.ps1 -ServiceKeyPath .\servicekey.json -OutputPath .\cert.pfx -Password $sec
    (non-interactive, e.g. for automation)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ServiceKeyPath,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath,

    [Parameter(Mandatory = $false)]
    [string]$JsonKeyPath = "uaa",

    [Parameter(Mandatory = $false)]
    [System.Security.SecureString]$Password
)

$ErrorActionPreference = "Stop"

Write-Host "=== Service Key -> PFX + PEM converter (pure PowerShell/.NET, no OpenSSL) ===" -ForegroundColor Green
Write-Host "PowerShell version: $($PSVersionTable.PSVersion)"

$release = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -ErrorAction SilentlyContinue).Release
if ($release -and $release -lt 528040) {
    Write-Host ".NET Framework 4.8 not detected (Release $release) - will use the built-in ASN.1 fallback parser for the private key." -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# Helpers: PEM handling
# ---------------------------------------------------------------------------

function Get-PemBlocks {
    <# Extracts all base64 blocks for a given PEM label (e.g. "CERTIFICATE")
       and returns them as an array of byte arrays. #>
    param(
        [Parameter(Mandatory)] [string] $PemText,
        [Parameter(Mandatory)] [string] $Label
    )
    $pattern = "-----BEGIN $Label-----(.*?)-----END $Label-----"
    $found = [System.Text.RegularExpressions.Regex]::Matches(
        $PemText, $pattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)
    $result = @()
    foreach ($m in $found) {
        $b64 = ($m.Groups[1].Value -replace '\s', '')
        $result += , ([Convert]::FromBase64String($b64))
    }
    # Unary comma operator: without it, PowerShell would unwrap a single-element
    # result array and hand the caller raw bytes instead of an array of blocks.
    return , $result
}

function Find-PrivateKeyLabel {
    <# Determines whether the key is PKCS#1 ("RSA PRIVATE KEY") or PKCS#8
       ("PRIVATE KEY"). #>
    param([Parameter(Mandatory)] [string] $PemText)
    if ($PemText -match '-----BEGIN RSA PRIVATE KEY-----') { return 'RSA PRIVATE KEY' }
    if ($PemText -match '-----BEGIN PRIVATE KEY-----') { return 'PRIVATE KEY' }
    if ($PemText -match '-----BEGIN ENCRYPTED PRIVATE KEY-----') {
        throw "Encrypted private keys (ENCRYPTED PRIVATE KEY) are not supported."
    }
    throw "No supported private key block (RSA PRIVATE KEY / PRIVATE KEY) found in the text."
}

# ---------------------------------------------------------------------------
# Helpers: minimal ASN.1/DER parser (fallback path, only what PKCS#1/#8 needs)
# ---------------------------------------------------------------------------

function Read-DerLength {
    param([Parameter(Mandatory)] [byte[]] $Bytes, [Parameter(Mandatory)] [ref] $Pos)
    $b = $Bytes[$Pos.Value]; $Pos.Value++
    if ($b -lt 0x80) { return [int]$b }
    $numBytes = $b -band 0x7F
    $len = 0
    for ($i = 0; $i -lt $numBytes; $i++) {
        $len = ($len -shl 8) -bor $Bytes[$Pos.Value]
        $Pos.Value++
    }
    return $len
}

function Read-DerTlv {
    <# Reads a single DER Tag-Length-Value element starting at $Pos. #>
    param([Parameter(Mandatory)] [byte[]] $Bytes, [Parameter(Mandatory)] [ref] $Pos)
    $tag = $Bytes[$Pos.Value]; $Pos.Value++
    $len = Read-DerLength -Bytes $Bytes -Pos $Pos
    if ($len -eq 0) {
        $value = New-Object byte[] 0
    }
    else {
        $value = $Bytes[$Pos.Value..($Pos.Value + $len - 1)]
    }
    $Pos.Value += $len
    return [PSCustomObject]@{ Tag = $tag; Value = $value }
}

function Read-DerInteger {
    param([Parameter(Mandatory)] [byte[]] $Bytes, [Parameter(Mandatory)] [ref] $Pos)
    $tlv = Read-DerTlv -Bytes $Bytes -Pos $Pos
    if ($tlv.Tag -ne 0x02) {
        throw "Expected DER INTEGER tag (0x02) not found (found: 0x$($tlv.Tag.ToString('X2')))."
    }
    return $tlv.Value
}

function Remove-LeadingZeroBytes {
    param([Parameter(Mandatory)] [byte[]] $Value)
    $i = 0
    while ($i -lt ($Value.Length - 1) -and $Value[$i] -eq 0) { $i++ }
    return $Value[$i..($Value.Length - 1)]
}

function Set-FixedLengthBytes {
    <# Pads/normalizes an integer byte array to exactly $Length bytes (left-padded with 0). #>
    param([Parameter(Mandatory)] [byte[]] $Value, [Parameter(Mandatory)] [int] $Length)
    $trimmed = Remove-LeadingZeroBytes -Value $Value
    if ($trimmed.Length -gt $Length) {
        throw "Unexpected field length while parsing the private key (expected <= $Length, got $($trimmed.Length))."
    }
    if ($trimmed.Length -eq $Length) { return $trimmed }
    $pad = New-Object byte[] ($Length - $trimmed.Length)
    return $pad + $trimmed
}

function ConvertFrom-Pkcs1RsaKey {
    <# Parses a PKCS#1 RSAPrivateKey (DER) per RFC 8017 Appendix A.1.2 and
       returns a System.Security.Cryptography.RSAParameters object. #>
    param([Parameter(Mandatory)] [byte[]] $Der)
    $pos = 0
    $seq = Read-DerTlv -Bytes $Der -Pos ([ref]$pos)
    if ($seq.Tag -ne 0x30) { throw "PKCS#1 key: no valid SEQUENCE found at the start." }

    $inner = $seq.Value
    $ipos = 0
    [void](Read-DerInteger -Bytes $inner -Pos ([ref]$ipos))   # version (unused)
    $n = Read-DerInteger -Bytes $inner -Pos ([ref]$ipos)      # modulus
    $e = Read-DerInteger -Bytes $inner -Pos ([ref]$ipos)      # publicExponent
    $d = Read-DerInteger -Bytes $inner -Pos ([ref]$ipos)      # privateExponent
    $p = Read-DerInteger -Bytes $inner -Pos ([ref]$ipos)      # prime1
    $q = Read-DerInteger -Bytes $inner -Pos ([ref]$ipos)      # prime2
    $dp = Read-DerInteger -Bytes $inner -Pos ([ref]$ipos)     # exponent1
    $dq = Read-DerInteger -Bytes $inner -Pos ([ref]$ipos)     # exponent2
    $iq = Read-DerInteger -Bytes $inner -Pos ([ref]$ipos)     # coefficient

    $modulus = Remove-LeadingZeroBytes -Value $n
    $modLen = $modulus.Length
    $halfLen = [int]($modLen / 2)

    $rsaParams = New-Object System.Security.Cryptography.RSAParameters
    $rsaParams.Modulus = $modulus
    $rsaParams.Exponent = Remove-LeadingZeroBytes -Value $e
    $rsaParams.D = Set-FixedLengthBytes -Value $d -Length $modLen
    $rsaParams.P = Set-FixedLengthBytes -Value $p -Length $halfLen
    $rsaParams.Q = Set-FixedLengthBytes -Value $q -Length $halfLen
    $rsaParams.DP = Set-FixedLengthBytes -Value $dp -Length $halfLen
    $rsaParams.DQ = Set-FixedLengthBytes -Value $dq -Length $halfLen
    $rsaParams.InverseQ = Set-FixedLengthBytes -Value $iq -Length $halfLen
    return $rsaParams
}

function ConvertFrom-Pkcs8RsaKey {
    <# Unwraps a PKCS#8 PrivateKeyInfo structure and returns the contained
       RSAParameters (RSA keys only). #>
    param([Parameter(Mandatory)] [byte[]] $Der)
    $pos = 0
    $seq = Read-DerTlv -Bytes $Der -Pos ([ref]$pos)
    if ($seq.Tag -ne 0x30) { throw "PKCS#8 key: no valid SEQUENCE found at the start." }

    $inner = $seq.Value
    $ipos = 0
    [void](Read-DerTlv -Bytes $inner -Pos ([ref]$ipos))       # version (INTEGER)
    [void](Read-DerTlv -Bytes $inner -Pos ([ref]$ipos))       # AlgorithmIdentifier (SEQUENCE)
    $keyOctet = Read-DerTlv -Bytes $inner -Pos ([ref]$ipos)   # privateKey (OCTET STRING)

    if ($keyOctet.Tag -ne 0x04) {
        throw "PKCS#8 key: expected OCTET STRING containing the actual key not found."
    }
    return ConvertFrom-Pkcs1RsaKey -Der $keyOctet.Value
}

function ConvertFrom-PemPrivateKeyManual {
    <# Fallback entry point: parses a PEM private key by hand via the ASN.1
       functions above and returns RSAParameters. #>
    param([Parameter(Mandatory)] [string] $PemText)
    $label = Find-PrivateKeyLabel -PemText $PemText
    $blocks = Get-PemBlocks -PemText $PemText -Label $label
    if ($blocks.Count -eq 0) {
        throw "Could not extract a '$label' block from the key text."
    }
    if ($label -eq 'RSA PRIVATE KEY') {
        return ConvertFrom-Pkcs1RsaKey -Der $blocks[0]
    }
    else {
        return ConvertFrom-Pkcs8RsaKey -Der $blocks[0]
    }
}

function Import-RsaPrivateKeyFromPem {
    <# Imports an RSA private key from PEM text. Tries .NET's native
       RSA.ImportRSAPrivateKey()/ImportPkcs8PrivateKey() first (fast, requires
       .NET Framework 4.8+); if that's unavailable or fails, transparently
       falls back to the manual ASN.1 parser above. Returns the RSA object. #>
    param([Parameter(Mandatory)] [string] $PemText)

    $label = Find-PrivateKeyLabel -PemText $PemText
    $blocks = Get-PemBlocks -PemText $PemText -Label $label
    if ($blocks.Count -eq 0) { throw "Could not extract a '$label' block from the key text." }

    $rsa = [System.Security.Cryptography.RSA]::Create()
    $usedFallback = $false
    try {
        [int]$bytesRead = 0
        if ($label -eq 'RSA PRIVATE KEY') {
            $rsa.ImportRSAPrivateKey([byte[]]$blocks[0], [ref]$bytesRead)
        }
        else {
            $rsa.ImportPkcs8PrivateKey([byte[]]$blocks[0], [ref]$bytesRead)
        }
    }
    catch {
        Write-Host "Native key import unavailable/failed ($($_.Exception.GetType().Name)) - using the built-in ASN.1 fallback parser." -ForegroundColor DarkGray
        $rsaParams = ConvertFrom-PemPrivateKeyManual -PemText $PemText
        $rsa.ImportParameters($rsaParams)
        $usedFallback = $true
    }
    return [PSCustomObject]@{ Rsa = $rsa; UsedFallback = $usedFallback }
}

function Test-KeyMatchesCertificate {
    <# Compares the RSA key's modulus against the certificate's public key
       modulus. Returns $true/$false. #>
    param(
        [Parameter(Mandatory)] [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate,
        [Parameter(Mandatory)] [System.Security.Cryptography.RSA] $Rsa
    )
    $certRsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($Certificate)
    if (-not $certRsa) { $certRsa = $Certificate.PublicKey.Key }
    if (-not $certRsa) {
        Write-Warning "Could not read the certificate's public key for comparison - continuing anyway."
        return $true
    }
    $certModulus = $certRsa.ExportParameters($false).Modulus
    $keyModulus = $Rsa.ExportParameters($false).Modulus
    $diff = Compare-Object -ReferenceObject $certModulus -DifferenceObject $keyModulus -SyncWindow 0
    return ($null -eq $diff)
}

function Read-MultilineInput {
    param([Parameter(Mandatory)] [string] $Prompt)
    Write-Host $Prompt -ForegroundColor Cyan
    Write-Host "(paste the content, then type 'EOF' on its own line and press Enter)" -ForegroundColor DarkGray
    $lines = New-Object System.Collections.Generic.List[string]
    while ($true) {
        $line = Read-Host
        if ($line -eq 'EOF') { break }
        $lines.Add($line)
    }
    return ($lines -join [Environment]::NewLine)
}

function Get-CertAndKeyFromJson {
    param([Parameter(Mandatory)] [string] $JsonText, [Parameter(Mandatory)] [string] $NodeName)
    try {
        $json = $JsonText | ConvertFrom-Json
    }
    catch {
        throw "JSON could not be parsed: $($_.Exception.Message)"
    }
    $node = $json.$NodeName
    if ($node -and $node.certificate -and $node.key) {
        return @{ Cert = $node.certificate; Key = $node.key }
    }
    if ($json.certificate -and $json.key) {
        return @{ Cert = $json.certificate; Key = $json.key }
    }
    throw "No '$NodeName.certificate'/'$NodeName.key' (or 'certificate'/'key') fields found in the JSON."
}

# ---------------------------------------------------------------------------
# 1. Determine certificate/key source (parameter or interactive menu)
# ---------------------------------------------------------------------------

$certPem = $null
$keyPem = $null
$rsa = $null
$rsaParams = $null
$plainPasswordForExport = $null

try {
    if ($ServiceKeyPath) {
        if (-not (Test-Path -LiteralPath $ServiceKeyPath)) { throw "Service key file not found: $ServiceKeyPath" }
        $jsonText = Get-Content -LiteralPath $ServiceKeyPath -Raw
        $data = Get-CertAndKeyFromJson -JsonText $jsonText -NodeName $JsonKeyPath
        $certPem = $data.Cert
        $keyPem = $data.Key
    }
    else {
        Write-Host ""
        Write-Host "How do you want to provide the certificate and key?"
        Write-Host "  [1] Path to a service key JSON file"
        Write-Host "  [2] Paste the service key JSON directly"
        Write-Host "  [3] Separate file paths for certificate and key"
        $mode = Read-Host "Choice (1/2/3)"

        switch ($mode) {
            '1' {
                $jsonPath = Read-Host "Path to the JSON file"
                if (-not (Test-Path -LiteralPath $jsonPath)) { throw "File not found: $jsonPath" }
                $jsonText = Get-Content -LiteralPath $jsonPath -Raw
                $data = Get-CertAndKeyFromJson -JsonText $jsonText -NodeName $JsonKeyPath
                $certPem = $data.Cert
                $keyPem = $data.Key
            }
            '2' {
                $jsonText = Read-MultilineInput -Prompt "Paste the full service key JSON block:"
                $data = Get-CertAndKeyFromJson -JsonText $jsonText -NodeName $JsonKeyPath
                $certPem = $data.Cert
                $keyPem = $data.Key
            }
            '3' {
                $certPath = Read-Host "Path to the certificate file (.crt/.pem)"
                $keyPath = Read-Host "Path to the key file (.key/.pem)"
                if (-not (Test-Path -LiteralPath $certPath)) { throw "Certificate file not found: $certPath" }
                if (-not (Test-Path -LiteralPath $keyPath)) { throw "Key file not found: $keyPath" }
                $certPem = Get-Content -LiteralPath $certPath -Raw
                $keyPem = Get-Content -LiteralPath $keyPath -Raw
            }
            default { throw "Invalid choice: $mode" }
        }
    }

    if ($certPem -notmatch '-----BEGIN CERTIFICATE-----') {
        throw "The certificate text does not contain a PEM certificate (BEGIN CERTIFICATE missing)."
    }
    if ($keyPem -notmatch '-----BEGIN (RSA )?PRIVATE KEY-----') {
        throw "The key text does not contain a supported PEM private key (PKCS#1/PKCS#8)."
    }
    Write-Host "Certificate and key loaded and validated successfully." -ForegroundColor Green

    # -----------------------------------------------------------------------
    # 2. Parse certificate chain + private key (native import, ASN.1 fallback)
    # -----------------------------------------------------------------------

    $certDerBlocks = Get-PemBlocks -PemText $certPem -Label 'CERTIFICATE'
    if ($certDerBlocks.Count -eq 0) { throw "No certificates found in the certificate text." }
    Write-Host "Certificates found in the chain: $($certDerBlocks.Count) (1 leaf + possible chain)" -ForegroundColor DarkGray

    $leafCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([byte[]]$certDerBlocks[0])

    $importResult = Import-RsaPrivateKeyFromPem -PemText $keyPem
    $rsa = $importResult.Rsa
    if ($importResult.UsedFallback) {
        Write-Host "Private key parsed via the built-in ASN.1 fallback parser." -ForegroundColor DarkGray
    }
    else {
        Write-Host "Private key parsed via .NET's native RSA import." -ForegroundColor DarkGray
    }

    # -----------------------------------------------------------------------
    # 3. Sanity check: does the key actually match the certificate?
    # -----------------------------------------------------------------------

    if (Test-KeyMatchesCertificate -Certificate $leafCert -Rsa $rsa) {
        Write-Host "Check passed: private key matches the certificate." -ForegroundColor Green
    }
    else {
        throw "The supplied private key does NOT match the certificate's public key (modulus differs). Check that certificate and key belong together."
    }

    # -----------------------------------------------------------------------
    # 4. Combine cert + key, build the export collection (leaf + chain)
    # -----------------------------------------------------------------------
    # X509Certificate2.CopyWithPrivateKey() requires .NET Framework 4.7.2+.
    # For maximum compatibility (down to very old .NET Framework versions)
    # this uses the classic route instead: export the full RSA key material
    # and attach it via the legacy CAPI-based RSACryptoServiceProvider and
    # the X509Certificate2.PrivateKey property, both available since .NET 1.1.
    #
    # Two details matter here, otherwise the exported .pfx ends up WITHOUT the
    # private key (only certificate bags, no shrouded keybag - which fails on
    # import elsewhere with "No key found in supplied blob"):
    #
    #  1. The key must live in a real, named, PERSISTED CSP container. The
    #     parameterless RSACryptoServiceProvider constructor gives an
    #     ephemeral key that Windows' native PFX export cannot serialize.
    #     A GUID container name avoids clashing with anything else; the
    #     container is deleted again in the finally block below.
    #  2. ProviderType 24 (PROV_RSA_AES, "Microsoft Enhanced RSA and AES
    #     Cryptographic Provider") instead of the legacy default type 1,
    #     since modern SHA-256 signed certificates need the AES-capable
    #     provider.
    #
    # Note: exportability is CAPI's default - there is no "Exportable" flag
    # in CspProviderFlags, only the opt-out UseNonExportableKey - so nothing
    # needs to be set for that.

    $fullRsaParams = $rsa.ExportParameters($true)
    $cspParams = New-Object System.Security.Cryptography.CspParameters
    $cspParams.KeyContainerName = "New-PfxFromServiceKey-$([Guid]::NewGuid().ToString())"
    $cspParams.ProviderType = 24
    $cspParams.ProviderName = "Microsoft Enhanced RSA and AES Cryptographic Provider"
    $csp = New-Object System.Security.Cryptography.RSACryptoServiceProvider($cspParams)
    $csp.PersistKeyInCsp = $true
    $csp.ImportParameters($fullRsaParams)
    $leafCert.PrivateKey = $csp
    $certWithKey = $leafCert

    if (-not $certWithKey.HasPrivateKey) {
        throw "Failed to attach the private key to the certificate (HasPrivateKey is false)."
    }

    $exportCollection = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
    [void]$exportCollection.Add($certWithKey)
    for ($i = 1; $i -lt $certDerBlocks.Count; $i++) {
        $chainCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([byte[]]$certDerBlocks[$i])
        [void]$exportCollection.Add($chainCert)
    }

    # -----------------------------------------------------------------------
    # 5. Output path (parameter or interactive with default suggestion)
    # -----------------------------------------------------------------------

    if (-not $OutputPath) {
        $scriptDir = $PSScriptRoot
        if ([string]::IsNullOrWhiteSpace($scriptDir)) { $scriptDir = (Get-Location).Path }
        $defaultPath = Join-Path -Path $scriptDir -ChildPath "$(Get-Date -Format 'yyyy-MM-dd-HH-mm').pfx"
        $inputPath = Read-Host "Output path for the pfx file [$defaultPath]"
        if ([string]::IsNullOrWhiteSpace($inputPath)) { $OutputPath = $defaultPath } else { $OutputPath = $inputPath }
    }
    if ([System.IO.Path]::GetExtension($OutputPath) -ne ".pfx") {
        $OutputPath = [System.IO.Path]::ChangeExtension($OutputPath, ".pfx")
    }
    $pemOutputPath = [System.IO.Path]::ChangeExtension($OutputPath, ".pem")

    $targetDir = Split-Path -Path $OutputPath -Parent
    if ($targetDir -and -not (Test-Path $targetDir)) {
        New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
        Write-Host "Directory created: $targetDir"
    }

    # -----------------------------------------------------------------------
    # 6. Password: parameter, auto-generate, or custom with confirmation
    # -----------------------------------------------------------------------

    if ($Password) {
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
        $plainPasswordForExport = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
    else {
        Write-Host ""
        Write-Host "  [1] Auto-generate a password (default)"
        Write-Host "  [2] Set my own password"
        $pwChoice = Read-Host "Choice (1/2) [1]"

        if ($pwChoice -eq "2") {
            do {
                $securePw1 = Read-Host "Set a password for the PFX file" -AsSecureString
                $securePw2 = Read-Host "Repeat the password" -AsSecureString
                $ptr1 = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePw1)
                $ptr2 = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePw2)
                $plain1 = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr1)
                $plain2 = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr2)
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr1)
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr2)
                if ($plain1 -ne $plain2) {
                    Write-Host "The two passwords do not match - please try again." -ForegroundColor Red
                }
            } while ($plain1 -ne $plain2)
            $plainPasswordForExport = $plain1
            $plain1 = $null; $plain2 = $null
        }
        else {
            $chars = (48..57) + (65..90) + (97..122)
            $plainPasswordForExport = -join ((1..20) | ForEach-Object { [char]($chars | Get-Random) })
            Write-Host ""
            Write-Host "Generated password: $plainPasswordForExport" -ForegroundColor Yellow
            Write-Host "Please save it securely right away (e.g. a password manager)." -ForegroundColor Yellow
        }
    }

    # -----------------------------------------------------------------------
    # 7. Export PFX + write the plain PEM bundle
    # -----------------------------------------------------------------------

    $pfxBytes = $exportCollection.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $plainPasswordForExport)
    [System.IO.File]::WriteAllBytes($OutputPath, $pfxBytes)

    # Verify the exported file really contains the private key. Windows can
    # silently produce a key-less PFX, which only surfaces much later as
    # "No key found in supplied blob" wherever the file gets imported - so
    # re-import it here and check while we can still fix it.
    $verifyCollection = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
    $verifyCollection.Import($OutputPath, $plainPasswordForExport,
        [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
    $verifiedLeaf = $null
    foreach ($c in $verifyCollection) {
        if ($c.HasPrivateKey) { $verifiedLeaf = $c; break }
    }
    if (-not $verifiedLeaf) {
        throw "Verification failed: the exported PFX contains no private key. Do not use this file."
    }
    Write-Host "Verification passed: exported PFX contains the private key." -ForegroundColor Green

    # The JSON's "\n" escapes are already real line breaks once parsed by
    # ConvertFrom-Json / read from a .pem file, so certPem/keyPem are already
    # valid PEM text and just need to be written out as-is.
    $pemContent = $certPem.TrimEnd() + "`r`n" + $keyPem.TrimEnd() + "`r`n"
    [System.IO.File]::WriteAllText($pemOutputPath, $pemContent)

    Write-Host ""
    Write-Host "=== Done ===" -ForegroundColor Green
    Write-Host "PFX path:    $OutputPath"
    Write-Host "PEM path:    $pemOutputPath (unencrypted - contains the private key, handle accordingly)"
    Write-Host "Subject:     $($leafCert.Subject)"
    Write-Host "Thumbprint:  $($leafCert.Thumbprint)"
    Write-Host "Valid until: $($leafCert.NotAfter)"
    Write-Host "Certificates included in PFX (leaf + chain): $($exportCollection.Count)"
}
catch {
    Write-Host ""
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
finally {
    # Wipe sensitive data from memory as best-effort
    if ($rsaParams) {
        $rsaParams.D = $null; $rsaParams.P = $null; $rsaParams.Q = $null
        $rsaParams.DP = $null; $rsaParams.DQ = $null; $rsaParams.InverseQ = $null
    }
    if ($fullRsaParams) {
        $fullRsaParams.D = $null; $fullRsaParams.P = $null; $fullRsaParams.Q = $null
        $fullRsaParams.DP = $null; $fullRsaParams.DQ = $null; $fullRsaParams.InverseQ = $null
    }
    if ($csp) {
        # PersistKeyInCsp = $false tells Windows to delete the key container
        # from the user's key store on disposal - otherwise the named,
        # exportable container created above would remain on disk forever.
        $csp.PersistKeyInCsp = $false
        $csp.Clear()
    }
    if ($rsa) { $rsa.Dispose() }
    $plainPasswordForExport = $null
    $keyPem = $null
    [System.GC]::Collect()
}
