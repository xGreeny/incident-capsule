function Get-ICStatusClass {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [string]$Status
    )

    switch ($Status) {
        'Succeeded'             { 'ok' }
        'Completed'             { 'ok' }
        'Partial'               { 'warn' }
        'CompletedWithWarnings' { 'warn' }
        'Failed'                { 'bad' }
        'CompletedWithErrors'   { 'bad' }
        default                 { 'neutral' }
    }
}

function ConvertTo-ICMetricRows {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$CollectorResults
    )

    $rows = New-Object System.Collections.Generic.List[string]
    foreach ($result in $CollectorResults) {
        if ($null -eq $result.metrics) {
            continue
        }
        foreach ($key in $result.metrics.Keys) {
            $value = $result.metrics[$key]
            if ($null -eq $value -or $value -is [System.Collections.IEnumerable] -and -not ($value -is [string])) {
                continue
            }
            $rows.Add(('<tr><td>{0}</td><td>{1}</td><td>{2}</td></tr>' -f
                (ConvertTo-ICHtml $result.name),
                (ConvertTo-ICHtml $key),
                (ConvertTo-ICHtml $value)))
        }
    }
    return $rows -join [Environment]::NewLine
}

function New-ICHtmlReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Context
    )

    $collectorRows = New-Object System.Collections.Generic.List[string]
    $warningBlocks = New-Object System.Collections.Generic.List[string]
    $evidenceBlocks = New-Object System.Collections.Generic.List[string]

    foreach ($result in @($Context.CollectorResults)) {
        $statusClass = Get-ICStatusClass -Status $result.status
        $duration = '{0:N1} s' -f ([double]$result.durationMilliseconds / 1000)
        $collectorRows.Add(('<tr><td>{0}</td><td><span class="pill {1}">{2}</span></td><td>{3}</td><td>{4}</td></tr>' -f
            (ConvertTo-ICHtml $result.name),
            $statusClass,
            (ConvertTo-ICHtml $result.status),
            (ConvertTo-ICHtml $duration),
            @($result.outputFiles).Count))

        $messages = @($result.warnings)
        if (-not [string]::IsNullOrWhiteSpace([string]$result.error)) {
            $messages += [string]$result.error
        }
        foreach ($message in $messages) {
            $warningBlocks.Add(('<li><strong>{0}</strong> — {1}</li>' -f
                (ConvertTo-ICHtml $result.name),
                (ConvertTo-ICHtml $message)))
        }

        $links = New-Object System.Collections.Generic.List[string]
        foreach ($relativePath in @($result.outputFiles)) {
            $href = '../' + ([string]$relativePath).Replace(' ', '%20')
            $links.Add(('<li><a href="{0}">{1}</a></li>' -f
                (ConvertTo-ICHtml $href),
                (ConvertTo-ICHtml $relativePath)))
        }
        if ($links.Count -eq 0) {
            $links.Add('<li class="muted">No output file recorded.</li>')
        }
        $evidenceBlocks.Add(('<details><summary>{0} <span class="muted">({1} file(s))</span></summary><ul>{2}</ul></details>' -f
            (ConvertTo-ICHtml $result.name),
            @($result.outputFiles).Count,
            ($links -join [Environment]::NewLine)))
    }

    if ($warningBlocks.Count -eq 0) {
        $warningBlocks.Add('<li class="ok-text">No collector warning or fatal error was recorded.</li>')
    }

    $completed = if ($null -ne $Context.CompletedAtUtc) { $Context.CompletedAtUtc } else { [datetime]::UtcNow }
    $duration = [math]::Round(($completed - $Context.StartedAtUtc).TotalSeconds, 2)
    $overallClass = Get-ICStatusClass -Status $Context.Status
    $metricRows = ConvertTo-ICMetricRows -CollectorResults @($Context.CollectorResults)
    if ([string]::IsNullOrWhiteSpace($metricRows)) {
        $metricRows = '<tr><td colspan="3" class="muted">No scalar metrics were reported.</td></tr>'
    }

    $html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Incident Capsule // $(ConvertTo-ICHtml $Context.CaseId) // $(ConvertTo-ICHtml $Context.HostName)</title>
<style>
:root{color-scheme:dark;--bg:#071015;--panel:#0d1820;--panel2:#101e27;--line:#20343f;--text:#d7e5e7;--muted:#7f9aa2;--green:#68f0ae;--cyan:#65d9ff;--amber:#ffcc66;--red:#ff6b7a;--neutral:#b9c8cc}*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:radial-gradient(circle at 20% 0,#102631 0,transparent 33%),var(--bg);color:var(--text);font:14px/1.55 ui-monospace,SFMono-Regular,Consolas,"Liberation Mono",monospace}.wrap{max-width:1240px;margin:auto;padding:30px}.hero,.panel,.card{border:1px solid var(--line);background:rgba(13,24,32,.95);box-shadow:0 16px 60px rgba(0,0,0,.22)}.hero{padding:26px;border-top:3px solid var(--green);border-radius:8px}.hero h1{margin:0;color:var(--green);font-size:28px;letter-spacing:.1em}.hero p{margin:6px 0 0;color:var(--muted)}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:18px 0}.card{padding:16px;border-radius:8px;min-width:0}.label{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.12em}.value{font-size:18px;margin-top:6px;overflow-wrap:anywhere}.panel{padding:19px;margin-top:14px;border-radius:8px}.panel h2{font-size:15px;color:var(--cyan);letter-spacing:.06em;margin:0 0 13px}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:10px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-weight:500}.pill{display:inline-block;border:1px solid currentColor;padding:2px 8px;border-radius:999px;font-size:11px}.ok{color:var(--green)}.warn{color:var(--amber)}.bad{color:var(--red)}.neutral{color:var(--neutral)}.ok-text{color:var(--green)}.muted{color:var(--muted)}ul{padding-left:23px}li{margin:5px 0}a{color:var(--cyan);text-decoration:none}a:hover{text-decoration:underline}details{border-top:1px solid var(--line);padding:10px 0}details:first-child{border-top:0}summary{cursor:pointer;color:var(--text)}code{color:var(--green)}.footer{color:var(--muted);margin:18px 0 2px;font-size:12px}.two{display:grid;grid-template-columns:1fr 1fr;gap:14px}@media(max-width:900px){.grid{grid-template-columns:1fr 1fr}.two{grid-template-columns:1fr}}@media(max-width:540px){.wrap{padding:12px}.grid{grid-template-columns:1fr}.hero h1{font-size:22px}table{display:block;overflow-x:auto}}
</style>
</head>
<body>
<main class="wrap">
<section class="hero">
  <h1>INCIDENT CAPSULE</h1>
  <p>WINDOWS FIRST-RESPONSE COLLECTION // OFFLINE REPORT // NO EXTERNAL RESOURCES</p>
</section>
<section class="grid">
  <div class="card"><div class="label">Case</div><div class="value">$(ConvertTo-ICHtml $Context.CaseId)</div></div>
  <div class="card"><div class="label">Host</div><div class="value">$(ConvertTo-ICHtml $Context.HostName)</div></div>
  <div class="card"><div class="label">Profile</div><div class="value">$(ConvertTo-ICHtml $Context.Profile)</div></div>
  <div class="card"><div class="label">Status</div><div class="value $overallClass">$(ConvertTo-ICHtml $Context.Status)</div></div>
</section>
<section class="two">
  <div class="panel">
    <h2>ACQUISITION</h2>
    <table><tbody>
      <tr><th>Capsule ID</th><td>$(ConvertTo-ICHtml $Context.CapsuleId)</td></tr>
      <tr><th>Operator</th><td>$(ConvertTo-ICHtml $Context.Operator)</td></tr>
      <tr><th>Elevated</th><td>$(ConvertTo-ICHtml $Context.IsElevated)</td></tr>
      <tr><th>Started UTC</th><td>$(ConvertTo-ICHtml $Context.StartedAtUtc.ToString('o'))</td></tr>
      <tr><th>Completed UTC</th><td>$(ConvertTo-ICHtml $completed.ToString('o'))</td></tr>
      <tr><th>Duration</th><td>$(ConvertTo-ICHtml $duration) s</td></tr>
    </tbody></table>
  </div>
  <div class="panel">
    <h2>INTEGRITY</h2>
    <table><tbody>
      <tr><th>Algorithm</th><td>SHA-256</td></tr>
      <tr><th>JSON manifest</th><td><a href="../metadata/manifest.json">metadata/manifest.json</a></td></tr>
      <tr><th>Checksum list</th><td><a href="../metadata/manifest.sha256">metadata/manifest.sha256</a></td></tr>
      <tr><th>Capsule metadata</th><td><a href="../metadata/capsule.json">metadata/capsule.json</a></td></tr>
      <tr><th>Collector log</th><td><a href="../logs/collector.log">logs/collector.log</a></td></tr>
      <tr><th>Verification</th><td><code>Test-IncidentCapsuleIntegrity</code></td></tr>
    </tbody></table>
  </div>
</section>
<section class="panel">
  <h2>COLLECTION STATUS</h2>
  <table><thead><tr><th>Collector</th><th>Status</th><th>Duration</th><th>Files</th></tr></thead><tbody>
    $($collectorRows -join [Environment]::NewLine)
  </tbody></table>
</section>
<section class="panel">
  <h2>COLLECTOR METRICS</h2>
  <table><thead><tr><th>Collector</th><th>Metric</th><th>Value</th></tr></thead><tbody>
    $metricRows
  </tbody></table>
</section>
<section class="panel">
  <h2>WARNINGS AND ERRORS</h2>
  <ul>$($warningBlocks -join [Environment]::NewLine)</ul>
</section>
<section class="panel">
  <h2>EVIDENCE INDEX</h2>
  $($evidenceBlocks -join [Environment]::NewLine)
</section>
<p class="footer">Generated offline by Incident Capsule $(ConvertTo-ICHtml $script:ICVersion). Preserve the original archive and verify hashes before analysis or transfer.</p>
</main>
</body>
</html>
"@

    return Write-ICUtf8File -Path $Context.ReportPath -Content $html
}
