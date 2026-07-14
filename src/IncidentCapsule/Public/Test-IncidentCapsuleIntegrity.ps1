function Test-IncidentCapsuleIntegrity {
    <#
    .SYNOPSIS
    Verifies an Incident Capsule directory or ZIP archive.

    .DESCRIPTION
    Validates the embedded SHA-256 manifest, conventional checksum list, and file set.
    ZIP archives are inspected against bounded path, entry-count, expanded-size, and
    compression-ratio policies before any entry is extracted. When an adjacent .sha256
    sidecar is present, its archive hash is also verified.

    .PARAMETER Path
    Path to a capsule directory or ZIP archive.

    .PARAMETER MaximumArchiveEntries
    Maximum number of entries accepted from an archive.

    .PARAMETER MaximumArchiveEntryBytes
    Maximum declared and extracted size of one archive entry.

    .PARAMETER MaximumArchiveExpandedBytes
    Maximum total expanded size accepted from an archive.

    .PARAMETER MaximumArchiveCompressionRatio
    Maximum ratio between an entry's expanded and compressed sizes.

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
        [string]$Path,

        [ValidateRange(1, 50000)]
        [int]$MaximumArchiveEntries = 20000,

        [ValidateRange(1, 2147483648L)]
        [int64]$MaximumArchiveEntryBytes = 1073741824L,

        [ValidateRange(1, 21474836480L)]
        [int64]$MaximumArchiveExpandedBytes = 10737418240L,

        [ValidateRange(1, 1000)]
        [int]$MaximumArchiveCompressionRatio = 250
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

        Test-ICArchiveIntegrity `
            -ArchivePath $resolved `
            -MaximumArchiveEntries $MaximumArchiveEntries `
            -MaximumArchiveEntryBytes $MaximumArchiveEntryBytes `
            -MaximumArchiveExpandedBytes $MaximumArchiveExpandedBytes `
            -MaximumArchiveCompressionRatio $MaximumArchiveCompressionRatio
    }
}
