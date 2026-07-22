function Export-IncidentCapsuleData {
    <#
    .SYNOPSIS
    Exports capsule evidence envelopes as line-delimited JSON (JSONL).

    .DESCRIPTION
    Reads the structured evidence envelopes of a collected capsule directory and
    writes one JSON object per evidence record, suitable for ingestion into SIEM
    and timeline tooling. Every line carries the capsule ID, host, collector,
    capture time, the capsule-relative source file, and the zero-based record
    index alongside the unmodified record.

    The export is written outside the capsule directory so the sealed evidence
    and its manifest remain untouched. Archives are not read directly: verify and
    extract them first with Test-IncidentCapsuleIntegrity.

    .PARAMETER Path
    Path to a collected capsule directory.

    .PARAMETER DestinationPath
    Optional output file. Defaults to '<capsule>.evidence.jsonl' beside the
    capsule directory. The destination must not already exist and must be
    outside the capsule directory.

    .PARAMETER Collector
    Optional collector names. Only envelopes written by these collectors are
    exported.

    .EXAMPLE
    Export-IncidentCapsuleData -Path $result.WorkingDirectory

    .EXAMPLE
    Export-IncidentCapsuleData -Path 'E:\Evidence\IC_IR-2026-0042_WS-042_20260712T184233Z_a1b2c3d4' -Collector Processes,Network -DestinationPath 'E:\Evidence\processes-network.jsonl'

    .OUTPUTS
    IncidentCapsule.ExportResult
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('FullName', 'WorkingDirectory')]
        [string]$Path,

        [string]$DestinationPath,

        [string[]]$Collector
    )

    process {
        $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
        if (-not (Test-Path -LiteralPath $resolved -PathType Container)) {
            throw "Path '$resolved' is not a capsule directory. Verify and extract an archive with Test-IncidentCapsuleIntegrity before exporting."
        }

        $root = Find-ICManifestRoot -Path $resolved
        $destination = if ($PSBoundParameters.ContainsKey('DestinationPath') -and -not [string]::IsNullOrWhiteSpace($DestinationPath)) {
            [System.IO.Path]::GetFullPath($DestinationPath)
        }
        else {
            "$root.evidence.jsonl"
        }

        $rootPrefix = $root + [System.IO.Path]::DirectorySeparatorChar
        if ($destination -eq $root -or $destination.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "DestinationPath '$destination' is inside the capsule directory; the sealed capsule must not be modified."
        }
        if (Test-Path -LiteralPath $destination) {
            throw "DestinationPath '$destination' already exists."
        }

        $evidenceRoot = Join-Path $root 'evidence'
        if (-not (Test-Path -LiteralPath $evidenceRoot -PathType Container)) {
            throw "Capsule '$root' does not contain an evidence directory."
        }

        $destinationDirectory = Split-Path -Parent $destination
        if (-not [string]::IsNullOrWhiteSpace($destinationDirectory) -and -not (Test-Path -LiteralPath $destinationDirectory)) {
            New-Item -ItemType Directory -Path $destinationDirectory -Force -ErrorAction Stop | Out-Null
        }

        $envelopeCount = 0
        $recordCount = 0
        $skippedFiles = New-Object System.Collections.ArrayList
        $collectorsSeen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)

        $encoding = New-Object System.Text.UTF8Encoding($false)
        $stream = New-Object System.IO.FileStream($destination, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        $writer = New-Object System.IO.StreamWriter($stream, $encoding)
        try {
            foreach ($file in Get-ChildItem -LiteralPath $evidenceRoot -Filter '*.json' -File -Recurse -ErrorAction Stop | Sort-Object FullName) {
                $relativePath = Get-ICRelativePath -BasePath $root -Path $file.FullName
                $envelope = $null
                try {
                    $envelope = Get-Content -LiteralPath $file.FullName -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                }
                catch {
                    [void]$skippedFiles.Add($relativePath)
                    continue
                }

                if (-not (Test-ICObjectProperty -InputObject $envelope -Name 'collector') -or -not (Test-ICObjectProperty -InputObject $envelope -Name 'data')) {
                    [void]$skippedFiles.Add($relativePath)
                    continue
                }

                $collectorName = [string]$envelope.collector
                if ($null -ne $Collector -and $Collector.Count -gt 0 -and $collectorName -notin $Collector) {
                    continue
                }

                $envelopeCount++
                [void]$collectorsSeen.Add($collectorName)

                $data = $envelope.data
                $records = if ($null -eq $data) { @() } elseif ($data -is [System.Array]) { @($data) } else { @($data) }
                $recordIndex = -1
                foreach ($record in $records) {
                    $recordIndex++
                    $line = [ordered]@{
                        capsuleId     = [string](Get-ICPropertyValue -InputObject $envelope -Name 'capsuleId')
                        host          = [string](Get-ICPropertyValue -InputObject $envelope -Name 'host')
                        collector     = $collectorName
                        capturedAtUtc = [string](Get-ICPropertyValue -InputObject $envelope -Name 'capturedAtUtc')
                        source        = $relativePath
                        recordIndex   = $recordIndex
                        record        = $record
                    }
                    $writer.WriteLine((ConvertTo-Json -InputObject $line -Compress -Depth 30))
                    $recordCount++
                }
            }
            $writer.Flush()
        }
        catch {
            $writer.Dispose()
            Remove-Item -LiteralPath $destination -Force -ErrorAction SilentlyContinue
            throw
        }
        finally {
            $writer.Dispose()
        }

        return [pscustomobject][ordered]@{
            PSTypeName    = 'IncidentCapsule.ExportResult'
            Path          = $destination
            CapsulePath   = $root
            EnvelopeCount = $envelopeCount
            RecordCount   = $recordCount
            SkippedFiles  = @($skippedFiles)
            Collectors    = @($collectorsSeen | Sort-Object)
        }
    }
}
