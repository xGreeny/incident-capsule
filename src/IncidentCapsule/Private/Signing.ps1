function Import-ICPkcsAssembly {
    [CmdletBinding()]
    param()

    if ($PSVersionTable.PSEdition -eq 'Desktop') {
        Add-Type -AssemblyName System.Security -ErrorAction Stop
    }
    else {
        Add-Type -AssemblyName System.Security.Cryptography.Pkcs -ErrorAction Stop
    }
}

function Resolve-ICSigningCertificate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Certificate
    )

    $resolved = $null
    if ($Certificate -is [System.Security.Cryptography.X509Certificates.X509Certificate2]) {
        $resolved = $Certificate
    }
    elseif ($Certificate -is [string]) {
        $thumbprint = ($Certificate -replace '[\s:]', '').ToUpperInvariant()
        if ($thumbprint -notmatch '^[A-F0-9]{40}$' -and $thumbprint -notmatch '^[A-F0-9]{64}$') {
            throw "SigningCertificate '$Certificate' is neither a certificate object nor a valid thumbprint."
        }
        foreach ($storePath in @('Cert:\CurrentUser\My', 'Cert:\LocalMachine\My')) {
            $candidate = @(
                Get-ChildItem -LiteralPath $storePath -ErrorAction SilentlyContinue |
                    Where-Object { $_.Thumbprint -eq $thumbprint } |
                    Select-Object -First 1
            )
            if ($candidate.Count -gt 0) {
                $resolved = $candidate[0]
                break
            }
        }
        if ($null -eq $resolved) {
            throw "No certificate with thumbprint '$thumbprint' was found in Cert:\CurrentUser\My or Cert:\LocalMachine\My."
        }
    }
    else {
        throw 'SigningCertificate must be an X509Certificate2 object or a thumbprint string.'
    }

    if (-not $resolved.HasPrivateKey) {
        throw "Certificate '$($resolved.Thumbprint)' has no accessible private key and cannot sign the manifest."
    }

    return $resolved
}

function New-ICManifestSignature {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ManifestTextPath,

        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    Import-ICPkcsAssembly
    $content = [System.IO.File]::ReadAllBytes($ManifestTextPath)
    $contentInfo = New-Object System.Security.Cryptography.Pkcs.ContentInfo (, $content)
    $signedCms = New-Object System.Security.Cryptography.Pkcs.SignedCms ($contentInfo, $true)
    $signer = New-Object System.Security.Cryptography.Pkcs.CmsSigner ($Certificate)
    # Silent signing only: a signing provider that requires interaction must fail
    # instead of blocking an unattended acquisition.
    $signedCms.ComputeSignature($signer, $true)

    $signaturePath = "$ManifestTextPath.p7s"
    [System.IO.File]::WriteAllBytes($signaturePath, $signedCms.Encode())

    return [pscustomobject][ordered]@{
        SignaturePath     = $signaturePath
        SignerSubject     = [string]$Certificate.Subject
        SignerThumbprint  = [string]$Certificate.Thumbprint
        SignerNotAfterUtc = ConvertTo-ICIso8601 -Value $Certificate.NotAfter
    }
}

function Test-ICManifestSignature {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ManifestTextPath,

        [Parameter(Mandatory)]
        [string]$SignaturePath
    )

    Import-ICPkcsAssembly
    $signatureValid = $false
    $signerSubject = $null
    $signerThumbprint = $null
    $chainValid = $null
    $chainStatus = @()
    $errorMessage = $null

    try {
        $content = [System.IO.File]::ReadAllBytes($ManifestTextPath)
        $signatureBytes = [System.IO.File]::ReadAllBytes($SignaturePath)
        $contentInfo = New-Object System.Security.Cryptography.Pkcs.ContentInfo (, $content)
        $signedCms = New-Object System.Security.Cryptography.Pkcs.SignedCms ($contentInfo, $true)
        $signedCms.Decode($signatureBytes)
        $signedCms.CheckSignature($true)
        $signatureValid = $true

        if ($signedCms.SignerInfos.Count -gt 0) {
            $signerCertificate = $signedCms.SignerInfos[0].Certificate
            if ($null -ne $signerCertificate) {
                $signerSubject = [string]$signerCertificate.Subject
                $signerThumbprint = [string]$signerCertificate.Thumbprint

                # Chain trust is reported separately from cryptographic validity:
                # verification must work offline, so revocation is not checked here.
                $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
                try {
                    $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
                    $chainValid = [bool]$chain.Build($signerCertificate)
                    $chainStatus = @($chain.ChainStatus | ForEach-Object { [string]$_.Status } | Select-Object -Unique)
                }
                finally {
                    try { $chain.Dispose() } catch { $null = $_ }
                }
            }
        }
    }
    catch {
        $errorMessage = $_.Exception.Message
    }

    return [pscustomobject][ordered]@{
        SignatureValid   = $signatureValid
        SignerSubject    = $signerSubject
        SignerThumbprint = $signerThumbprint
        ChainValid       = $chainValid
        ChainStatus      = @($chainStatus)
        Error            = $errorMessage
    }
}
