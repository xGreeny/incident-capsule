function Test-IncidentCapsuleIntegrity {
    <#
    .SYNOPSIS
    Verifies an Incident Capsule directory or ZIP archive.

    .DESCRIPTION
    Checks the embedded SHA-256 manifest for missing, modified, and unexpected files.
    For a ZIP archive, the adjacent .sha256 sidecar is verified when present before
    the archive is extracted to a temporary directory and the embedded manifest is checked.

    .PARAMETER Path
    Path to a capsule directory or ZIP archive.

    .EXAMPLE
    Test-IncidentCapsuleIntegrity -Path 'E:\Evidence\IC_IR-2026-0042_WS-042_20260712T184233Z.zip'

    .EXAMPLE
    $result = Test-IncidentCapsuleIntegrity -Path $capsule.WorkingDirectory
    $result.FileResults | Where-Object Status -ne 'Valid'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('FullName')]
        [string]$Path
    )

    process {
        $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
        if (Test-Path -LiteralPath $resolved -PathType Container) {
            $root = Find-ICManifestRoot -Path $resolved
            Test-ICDirectoryIntegrity -CapsuleRoot $root
            return
        }

        if ([System.IO.Path]::GetExtension($resolved) -ne '.zip') {
            throw "Path '$resolved' is neither a directory nor a ZIP archive."
        }

        $archiveHashValid = $null
        $sidecarPath = "$resolved.sha256"
        if (Test-Path -LiteralPath $sidecarPath -PathType Leaf) {
            $line = (Get-Content -LiteralPath $sidecarPath -Encoding UTF8 | Select-Object -First 1)
            $expectedHash = ([string]$line -split '\s+')[0].Trim().ToLowerInvariant()
            if ($expectedHash -notmatch '^[a-f0-9]{64}$') {
                throw "Sidecar '$sidecarPath' does not contain a valid SHA-256 value."
            }
            $actualHash = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash.ToLowerInvariant()
            $archiveHashValid = $actualHash -eq $expectedHash
        }

        $temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("incident-capsule-verify-{0}" -f [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $temporaryRoot -Force | Out-Null
        try {
            Expand-Archive -LiteralPath $resolved -DestinationPath $temporaryRoot -Force
            $root = Find-ICManifestRoot -Path $temporaryRoot
            $result = Test-ICDirectoryIntegrity -CapsuleRoot $root
            $result.Path = $resolved
            $result.SourceType = 'Archive'
            $result.ArchiveHashValid = $archiveHashValid
            if ($archiveHashValid -eq $false) {
                $result.IsValid = $false
            }
            $result
        }
        finally {
            Remove-Item -LiteralPath $temporaryRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
