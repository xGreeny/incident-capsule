function Get-ICCertificateEnhancedKeyUsage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    $usages = New-Object System.Collections.ArrayList
    foreach ($extension in @($Certificate.Extensions)) {
        if ($extension -isnot [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]) {
            continue
        }
        foreach ($oid in @($extension.EnhancedKeyUsages)) {
            $label = if (-not [string]::IsNullOrWhiteSpace($oid.FriendlyName)) { $oid.FriendlyName } else { $oid.Value }
            if (-not [string]::IsNullOrWhiteSpace($label)) {
                [void]$usages.Add($label)
            }
        }
    }
    return ($usages -join '; ')
}

function Get-ICCertificateEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Context
    )

    $warnings = New-Object System.Collections.ArrayList
    $files = New-Object System.Collections.ArrayList

    $stores = @('Root', 'CA', 'AuthRoot', 'TrustedPublisher', 'TrustedPeople', 'Disallowed')
    $entries = New-Object System.Collections.ArrayList
    $storesQueried = 0
    foreach ($storeName in $stores) {
        $storePath = "Cert:\LocalMachine\$storeName"
        if (-not (Test-Path -LiteralPath $storePath)) {
            Add-ICCollectorWarning -List $warnings -Message "Certificate store '$storeName' is unavailable."
            continue
        }
        try {
            $storesQueried++
            foreach ($certificate in Get-ChildItem -LiteralPath $storePath -ErrorAction Stop) {
                if ($certificate -isnot [System.Security.Cryptography.X509Certificates.X509Certificate2]) {
                    continue
                }
                $signatureAlgorithm = $null
                try { $signatureAlgorithm = $certificate.SignatureAlgorithm.FriendlyName } catch { $signatureAlgorithm = $null }
                $keyAlgorithm = $null
                try { $keyAlgorithm = $certificate.PublicKey.Oid.FriendlyName } catch { $keyAlgorithm = $null }

                [void]$entries.Add([pscustomobject][ordered]@{
                    Store              = $storeName
                    Subject            = [string]$certificate.Subject
                    Issuer             = [string]$certificate.Issuer
                    Thumbprint         = [string]$certificate.Thumbprint
                    SerialNumber       = [string]$certificate.SerialNumber
                    NotBeforeUtc       = ConvertTo-ICIso8601 -Value $certificate.NotBefore
                    NotAfterUtc        = ConvertTo-ICIso8601 -Value $certificate.NotAfter
                    SignatureAlgorithm = $signatureAlgorithm
                    KeyAlgorithm       = $keyAlgorithm
                    EnhancedKeyUsages  = Get-ICCertificateEnhancedKeyUsage -Certificate $certificate
                    IsSelfSigned       = ($certificate.Subject -eq $certificate.Issuer)
                    HasPrivateKey      = [bool]$certificate.HasPrivateKey
                    Archived           = [bool]$certificate.Archived
                })
            }
        }
        catch { Add-ICCollectorWarning -List $warnings -Message "Certificate store '$storeName': $($_.Exception.Message)" }
    }

    $sorted = @($entries | Sort-Object Store, Subject, Thumbprint)
    Add-ICOutputFiles -List $files -Path (Export-ICCollectorData -Context $Context -Collector Certificates -RelativePath 'evidence/certificates/certificate-stores.json' -Data $sorted -Csv)

    return New-ICCollectorResultData -OutputFiles @($files) -Warnings @($warnings) -Metrics ([ordered]@{
        CertificateCount       = $sorted.Count
        StoresQueried          = $storesQueried
        NonSelfSignedRootEntries = @($sorted | Where-Object { $_.Store -eq 'Root' -and $_.IsSelfSigned -eq $false }).Count
        DisallowedEntries      = @($sorted | Where-Object Store -eq 'Disallowed').Count
    })
}
