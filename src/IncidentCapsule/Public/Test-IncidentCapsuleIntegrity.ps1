function Test-IncidentCapsuleIntegrity {
    <#
    .SYNOPSIS
    Verifies an Incident Capsule directory or ZIP archive.

    .DESCRIPTION
    Validates the embedded SHA-256 manifest, conventional checksum list, and file set.
    ZIP archives are inspected for unsafe paths, link metadata, duplicate entries, and
    bounded entry count, per-entry size, expanded size, and compression ratio before
    extraction. An adjacent .sha256 sidecar is verified when present.

    .PARAMETER Path
    Path to a capsule directory or ZIP archive.

    .PARAMETER RequireSidecar
    Reject a ZIP archive when its adjacent .sha256 sidecar is missing.

    .PARAMETER MaximumArchiveEntries
    Maximum number of ZIP entries inspected and extracted.

    .PARAMETER MaximumArchiveEntryBytes
    Maximum declared and extracted size of one ZIP entry.

    .PARAMETER MaximumArchiveExpandedBytes
    Maximum total expanded ZIP size. MaximumArchiveUncompressedBytes remains an alias.

    .PARAMETER MaximumArchiveCompressionRatio
    Maximum per-entry and aggregate ZIP compression ratio.

    .EXAMPLE
    Test-IncidentCapsuleIntegrity -Path 'E:\Evidence\IC_IR-2026-0042_WS-042_20260712T184233Z.zip' -RequireSidecar

    .EXAMPLE
    $result = Test-IncidentCapsuleIntegrity -Path $capsule.WorkingDirectory
    $result.FileResults | Where-Object Status -ne 'Valid'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('FullName')]
        [string]$Path,

        [switch]$RequireSidecar,

        [ValidateRange(1, 50000)]
        [int]$MaximumArchiveEntries = 20000,

        [ValidateRange(1, 8796093022208L)]
        [int64]$MaximumArchiveEntryBytes = 1073741824L,

        [Alias('MaximumArchiveUncompressedBytes')]
        [ValidateRange(1, 8796093022208L)]
        [int64]$MaximumArchiveExpandedBytes = 21474836480L,

        [ValidateRange(1, 1000)]
        [double]$MaximumArchiveCompressionRatio = 250
    )

    process {
        if ($MaximumArchiveEntryBytes -gt $MaximumArchiveExpandedBytes) {
            throw 'MaximumArchiveEntryBytes cannot exceed MaximumArchiveExpandedBytes.'
        }

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
            -RequireSidecar:$RequireSidecar `
            -MaximumArchiveEntries $MaximumArchiveEntries `
            -MaximumArchiveEntryBytes $MaximumArchiveEntryBytes `
            -MaximumArchiveExpandedBytes $MaximumArchiveExpandedBytes `
            -MaximumArchiveCompressionRatio $MaximumArchiveCompressionRatio
    }
}
