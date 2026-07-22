$repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$moduleManifest = Join-Path $repositoryRoot 'src/IncidentCapsule/IncidentCapsule.psd1'
Import-Module $moduleManifest -Force -ErrorAction Stop

Describe 'Incident Capsule manifest signing' {
    BeforeAll {
        $script:signingCertificate = New-SelfSignedCertificate `
            -Subject 'CN=IncidentCapsule Pester Signing' `
            -Type CodeSigningCert `
            -CertStoreLocation 'Cert:\CurrentUser\My' `
            -KeyExportPolicy Exportable `
            -NotAfter ([datetime]::Now.AddDays(2))

        function New-SignedTestCapsule {
            param(
                [Parameter(Mandatory)]
                [string]$Root,

                [Parameter(Mandatory)]
                [object]$Certificate,

                [switch]$SkipSignature
            )

            New-Item -ItemType Directory -Path (Join-Path $Root 'evidence') -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $Root 'evidence/sample.json') -Value '{"data":[]}' -Encoding UTF8
            InModuleScope IncidentCapsule -Parameters @{ Root = $Root; Certificate = $Certificate; SkipSignature = [bool]$SkipSignature } {
                param($Root, $Certificate, $SkipSignature)
                $manifest = New-ICManifest -CapsuleRoot $Root -CapsuleId 'IC-SIGNING'
                if (-not $SkipSignature) {
                    [void](New-ICManifestSignature -ManifestTextPath $manifest.TextPath -Certificate $Certificate)
                }
            }
        }
    }

    AfterAll {
        if ($null -ne $script:signingCertificate) {
            Remove-Item -LiteralPath (Join-Path 'Cert:\CurrentUser\My' $script:signingCertificate.Thumbprint) -Force -ErrorAction SilentlyContinue
        }
    }

    It 'signs the checksum list and verifies the signature during directory integrity' {
        $root = Join-Path $TestDrive 'signed-directory'
        New-SignedTestCapsule -Root $root -Certificate $script:signingCertificate

        (Join-Path $root 'metadata/manifest.sha256.p7s') | Should -Exist
        $result = Test-IncidentCapsuleIntegrity -Path $root -RequireSignature
        $result.IsValid | Should -BeTrue
        $result.SignaturePresent | Should -BeTrue
        $result.SignatureValid | Should -BeTrue
        $result.SignerThumbprint | Should -Be $script:signingCertificate.Thumbprint
    }

    It 'keeps unsigned capsules valid but fails a signature requirement' {
        $root = Join-Path $TestDrive 'unsigned-directory'
        New-SignedTestCapsule -Root $root -Certificate $script:signingCertificate -SkipSignature

        $result = Test-IncidentCapsuleIntegrity -Path $root
        $result.IsValid | Should -BeTrue
        $result.SignaturePresent | Should -BeFalse
        $result.SignatureValid | Should -BeNullOrEmpty

        { Test-IncidentCapsuleIntegrity -Path $root -RequireSignature } | Should -Throw '*manifest signature*'
    }

    It 'invalidates the capsule when the signed checksum list is altered' {
        $root = Join-Path $TestDrive 'tampered-directory'
        New-SignedTestCapsule -Root $root -Certificate $script:signingCertificate

        $checksumPath = Join-Path $root 'metadata/manifest.sha256'
        $content = [System.IO.File]::ReadAllText($checksumPath)
        [System.IO.File]::WriteAllText($checksumPath, $content.Replace('evidence/sample.json', 'evidence/sampled.json'))

        $verification = InModuleScope IncidentCapsule -Parameters @{ Root = $root } {
            param($Root)
            Test-ICManifestSignature `
                -ManifestTextPath (Join-Path $Root 'metadata/manifest.sha256') `
                -SignaturePath (Join-Path $Root 'metadata/manifest.sha256.p7s')
        }

        $verification.SignatureValid | Should -BeFalse
    }

    It 'carries the signature through archive creation and verification' {
        $root = Join-Path $TestDrive 'signed-archive'
        New-SignedTestCapsule -Root $root -Certificate $script:signingCertificate

        $archive = InModuleScope IncidentCapsule -Parameters @{ Root = $root } {
            param($Root)
            New-ICArchive -CapsuleRoot $Root
        }

        $result = Test-IncidentCapsuleIntegrity -Path $archive.ArchivePath -RequireSidecar -RequireSignature
        $result.IsValid | Should -BeTrue
        $result.SignaturePresent | Should -BeTrue
        $result.SignatureValid | Should -BeTrue
    }

    It 'resolves a signing certificate by thumbprint' {
        InModuleScope IncidentCapsule -Parameters @{ Thumbprint = $script:signingCertificate.Thumbprint } {
            param($Thumbprint)
            $resolved = Resolve-ICSigningCertificate -Certificate $Thumbprint
            $resolved.Thumbprint | Should -Be $Thumbprint
        }
    }

    It 'rejects a certificate without an accessible private key' {
        $publicOnly = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (, $script:signingCertificate.RawData)
        InModuleScope IncidentCapsule -Parameters @{ Certificate = $publicOnly } {
            param($Certificate)
            $thrown = $null
            try { Resolve-ICSigningCertificate -Certificate $Certificate } catch { $thrown = $_.Exception.Message }
            $thrown | Should -Match 'private key'
        }
    }
}
