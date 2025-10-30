<#
.SYNOPSIS
  Scan HVCI (Memory Integrity readiness) sur un parc AD.
  PS7 => parallèle ; PS5 => jobs. Export CSV compatible Excel FR (UTF-8 BOM, séparateur culture).

.OUTPUT
  CSV avec : ComputerName, Reachable, UsedWinRM, ExitCode,
             HvciPassed, HvciMessage, IssuesHex, IssuesFlags, VbsIsRecommended,
             IncompatibleDrivers, IncompatibleInfs, RemoteExe [, RawOutput si -IncludeRawOutput], Error, ScanTimeUtc

.NOTES
  - Préfère -ScannerPath (copie locale) à -NetworkScannerPath (UNC) pour éviter le double-hop.
  - Droits admin requis. Partages admin \\C$\… utiles si WinRM indisponible.
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$false)]
  [string]$ScannerPath,

  [Parameter(Mandatory=$false)]
  [string]$NetworkScannerPath,

  [Parameter(Mandatory=$true)]
  [string]$OutputCsv,

  [Parameter(Mandatory=$false)]
  [string]$OUDN,

  [Parameter(Mandatory=$false)]
  [string]$Filter = '(enabled -eq $true)',

  [Parameter(Mandatory=$false)]
  [string[]]$ComputerName,

  [int]$MaxConcurrency = 24,
  [int]$TimeOutSec = 180,
  [string]$RemoteWorkDir = 'C:\ProgramData\Audit\Tools\HVCI',
  [switch]$KeepRemoteCopy,

  # Pour garder la sortie brute (aplanie) en plus du tableau synthétique
  [switch]$IncludeRawOutput
)

# ------------------- Cibles
if (-not $ComputerName) {
  try { Import-Module ActiveDirectory -ErrorAction Stop } catch { throw "Module ActiveDirectory requis (RSAT)." }
  $rootDN = (Get-ADDomain).DistinguishedName
  $searchBase = $rootDN
  if ($OUDN) {
    try { Get-ADObject -Identity $OUDN -ErrorAction Stop | Out-Null; $searchBase = $OUDN }
    catch { Write-Warning "OUDN invalide: '$OUDN'. Utilisation de la racine: $rootDN" }
  }
  $adParams = @{ Filter = $Filter; Properties = @('Enabled','OperatingSystem'); SearchBase = $searchBase }
  $ComputerName = (Get-ADComputer @adParams | Where-Object Enabled | Select-Object -ExpandProperty Name)
}
if (-not $ComputerName -or $ComputerName.Count -eq 0) { Write-Warning "Aucune machine trouvée via AD."; $ComputerName = @() }

# ------------------- Entrées
if (-not $ScannerPath -and -not $NetworkScannerPath) { throw "Fournis -ScannerPath (copie) ou -NetworkScannerPath (UNC)." }
if ($ScannerPath -and -not (Test-Path $ScannerPath)) { throw "Scanner introuvable: $ScannerPath" }

# Dossier export
$csvDir = Split-Path $OutputCsv -Parent
if ($csvDir -and -not (Test-Path $csvDir)) { New-Item -ItemType Directory -Path $csvDir -Force | Out-Null }

# ------------------- Worker PS5 (jobs) — parseur + flags + verdict inclus
$ps5Worker = {
  param($Computer,$ScannerPathLocal,$NetworkScannerPathArg,$TimeOutSecArg,$RemoteWorkDirArg,[bool]$KeepCopy)

  function Parse-LocalHvciScanText([string]$Text) {
    $drivers = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $infs    = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    if ($Text) {
      foreach ($line in ($Text -split "`r?`n")) {
        foreach ($m in [regex]::Matches($line, '(?<sys>[A-Za-z0-9_\-\.\\: ]+?\.sys)\b')) { $null = $drivers.Add($m.Groups['sys'].Value.Trim()) }
        foreach ($m in [regex]::Matches($line, '(?<inf>oem\d+\.inf|\w[\w\-\._]*\.inf)\b')) { $null = $infs.Add($m.Groups['inf'].Value.Trim()) }
      }
    }
    [pscustomobject]@{ Drivers=@($drivers); Infs=@($infs) }
  }

  function Get-PreScanIssuesFlags([string]$Text) {
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $lines = @()
    foreach ($raw in ($Text -split "`r?`n")) {
      $t = $raw.Trim()
      if ([string]::IsNullOrWhiteSpace($t)) { continue }
      if ($t -match '^HVCI incompatible driver scan start') { break }
      if ($t -match '^(VbsGetIssues|VbsIsRecommended)\s*:') { continue }
      $lines += $t
    }
    if ($lines.Count -gt 0) { $lines -join ' | ' } else { $null }
  }

  $reachable=$false;$usedWinRM=$false;$exitCode=$null;$rawOut='';$errText='';$drv=@();$inf=@();$remoteExe=''
  $issuesHex=$null;$issuesFlags=$null;$vbsRec=$null;$hvciPassed=$null;$hvciMsg=''
  $logsLocal = 'C:\ProgramData\Audit\Logs'

  try {
    if (-not (Test-Connection -ComputerName $Computer -Count 1 -Quiet -ErrorAction SilentlyContinue)) { throw "Hôte injoignable (ICMP)." }
    $reachable = $true

    $remoteToolsUNC = ("\\{0}\C$\{1}" -f $Computer, ($RemoteWorkDirArg -replace '^[A-Za-z]:\\',''))
    $remoteLogsUNC  = "\\$Computer\C$\ProgramData\Audit\Logs"
    foreach ($p in @($remoteToolsUNC,$remoteLogsUNC)) { if (-not (Test-Path $p)) { try { New-Item -ItemType Directory -Path $p -Force | Out-Null } catch {} } }

    if ($ScannerPathLocal) {
      $file = Split-Path $ScannerPathLocal -Leaf
      Copy-Item -Path $ScannerPathLocal -Destination (Join-Path $remoteToolsUNC $file) -Force
      $remoteExe = Join-Path $RemoteWorkDirArg $file
    } else {
      $remoteExe = $NetworkScannerPathArg
    }

    try {
      $s = New-PSSession -ComputerName $Computer -ErrorAction Stop
      try {
        $usedWinRM = $true
        $sb = {
          param($exe,$timeout)
          if (-not (Test-Path $exe)) { throw "Scanner introuvable: $exe" }
          $script = {
            param($e)
            $o = & $e 2>&1 | Out-String
            $ec = $LASTEXITCODE
            [pscustomobject]@{ ExitCode=$ec; Output=$o }
          }
          $j = Start-Job -ScriptBlock $script -ArgumentList $exe
          if (-not (Wait-Job -Job $j -Timeout $timeout)) { Stop-Job $j -Force; Remove-Job $j -Force; throw "Timeout après $timeout s." }
          $r = Receive-Job $j; Remove-Job $j -Force
          [pscustomobject]@{ ExitCode=$r.ExitCode; StdOut=$r.Output; StdErr='' }
        }
        $r = Invoke-Command -Session $s -ScriptBlock $sb -ArgumentList $remoteExe, $TimeOutSecArg -ErrorAction Stop
        $rawOut = ($r.StdOut + "`n" + $r.StdErr).Trim(); $exitCode=$r.ExitCode
      } finally { if ($s) { Remove-PSSession $s -ErrorAction SilentlyContinue } }
    } catch {
      # Fallback WMI (pas d’UNC)
      $logLocal = "C:\ProgramData\Audit\Logs\hvci_scan.txt"
      if (-not $ScannerPathLocal) { throw "WMI fallback ne peut pas exécuter un UNC (LocalSystem sans accès réseau). Utilise -ScannerPath." }
      $null = Invoke-CimMethod -ComputerName $Computer -ClassName Win32_Process -MethodName Create -Arguments @{
        CommandLine = "cmd /c `"$remoteExe`" > `"$logLocal`" 2>&1"
      } -ErrorAction Stop
      $deadline = (Get-Date).AddSeconds($TimeOutSecArg); $ok=$false
      while ((Get-Date) -lt $deadline) { Start-Sleep 2; if (Test-Path (Join-Path $remoteLogsUNC 'hvci_scan.txt')) { $ok=$true; break } }
      if ($ok) { $rawOut = Get-Content (Join-Path $remoteLogsUNC 'hvci_scan.txt') -Raw } else { throw "Pas de sortie HVCI (WMI)." }
      $exitCode = 0
    }

    # Parsing + verdict
    $p = Parse-LocalHvciScanText -Text $rawOut; $drv=$p.Drivers; $inf=$p.Infs
    if ($rawOut -match 'VbsGetIssues:\s*(0x[0-9A-Fa-f]+)') { $issuesHex = $matches[1] }
    if ($rawOut -match 'VbsIsRecommended:\s*(\d+)')        { $vbsRec    = [int]$matches[1] }
    $issuesFlags = Get-PreScanIssuesFlags -Text $rawOut

    if ($rawOut -match '(?i)HVCI incompatible driver scan passed') { $hvciPassed = $true }
    elseif (($issuesHex -eq '0x00000000') -and ($drv.Count -eq 0) -and ($inf.Count -eq 0) -and ($exitCode -ge 0)) { $hvciPassed = $true }
    elseif (($drv.Count + $inf.Count) -gt 0) { $hvciPassed = $false }

    if ($hvciPassed -eq $true)      { $hvciMsg = 'HVCI incompatible driver scan passed!' }
    elseif ($hvciPassed -eq $false) { $hvciMsg = "HVCI scan: incompatibilités détectées (Drivers=$($drv.Count), INFs=$($inf.Count))" }
    else                            { $hvciMsg = 'HVCI scan: indéterminé (aucune sortie ou exécution incomplète)' }

    if ($ScannerPathLocal -and -not $KeepCopy) { try { Remove-Item (Join-Path $remoteToolsUNC (Split-Path $ScannerPathLocal -Leaf)) -Force } catch {} }
  }
  catch {
    $errText  = $_.Exception.Message
    if ([string]::IsNullOrWhiteSpace($rawOut)) { $rawOut = $errText }
    if ($null -eq $exitCode) { $exitCode = -1 }
    if (-not $hvciMsg) { $hvciMsg = 'HVCI scan: erreur' }
  }

  [pscustomobject]@{
    ComputerName        = $Computer
    Reachable           = $reachable
    UsedWinRM           = $usedWinRM
    ExitCode            = $exitCode
    HvciPassed          = $hvciPassed
    HvciMessage         = $hvciMsg
    IssuesHex           = $issuesHex
    IssuesFlags         = $issuesFlags
    VbsIsRecommended    = $vbsRec
    IncompatibleDrivers = ($drv -join '; ')
    IncompatibleInfs    = ($inf -join '; ')
    RemoteExe           = $remoteExe
    RawOutput           = $rawOut
    Error               = $errText
    ScanTimeUtc         = [DateTime]::UtcNow
  }
}

# ------------------- Exécution
$ts = Get-Date
$results = @()
try {
  if ($PSVersionTable.PSVersion.Major -ge 7) {
    Write-Host "PS7 détecté → exécution en parallèle (ThrottleLimit=$MaxConcurrency)..." -ForegroundColor Cyan

    $results = $ComputerName | ForEach-Object -Parallel {
      $comp = $_
      $TimeOutSec        = $using:TimeOutSec
      $RemoteWorkDir     = $using:RemoteWorkDir
      $ScannerPath       = $using:ScannerPath
      $NetworkScannerPath= $using:NetworkScannerPath
      $KeepRemoteCopy    = [bool]$using:KeepRemoteCopy

      function Parse-LocalHvciScanText([string]$Text) {
        $drivers = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $infs    = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        if ($Text) {
          foreach ($line in ($Text -split "`r?`n")) {
            foreach ($m in [regex]::Matches($line, '(?<sys>[A-Za-z0-9_\-\.\\: ]+?\.sys)\b')) { $null = $drivers.Add($m.Groups['sys'].Value.Trim()) }
            foreach ($m in [regex]::Matches($line, '(?<inf>oem\d+\.inf|\w[\w\-\._]*\.inf)\b')) { $null = $infs.Add($m.Groups['inf'].Value.Trim()) }
          }
        }
        [pscustomobject]@{ Drivers=@($drivers); Infs=@($infs) }
      }

      function Get-PreScanIssuesFlags([string]$Text) {
        if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
        $lines = @()
        foreach ($raw in ($Text -split "`r?`n")) {
          $t = $raw.Trim()
          if ([string]::IsNullOrWhiteSpace($t)) { continue }
          if ($t -match '^HVCI incompatible driver scan start') { break }
          if ($t -match '^(VbsGetIssues|VbsIsRecommended)\s*:') { continue }
          $lines += $t
        }
        if ($lines.Count -gt 0) { $lines -join ' | ' } else { $null }
      }

      $reachable=$false;$usedWinRM=$false;$exitCode=$null;$rawOut='';$errText='';$drv=@();$inf=@();$remoteExe=''
      $issuesHex=$null;$issuesFlags=$null;$vbsRec=$null;$hvciPassed=$null;$hvciMsg=''
      $logsLocal = 'C:\ProgramData\Audit\Logs'

      try {
        if (-not (Test-Connection -ComputerName $comp -Count 1 -Quiet -ErrorAction SilentlyContinue)) { throw "Hôte injoignable (ICMP)." }
        $reachable = $true

        $remoteToolsUNC = ("\\{0}\C$\{1}" -f $comp, ($RemoteWorkDir -replace '^[A-Za-z]:\\',''))
        $remoteLogsUNC  = "\\$comp\C$\ProgramData\Audit\Logs"
        foreach ($p in @($remoteToolsUNC,$remoteLogsUNC)) { if (-not (Test-Path $p)) { try { New-Item -ItemType Directory -Path $p -Force | Out-Null } catch {} } }

        if ($ScannerPath) {
          $file = Split-Path $ScannerPath -Leaf
          Copy-Item -Path $ScannerPath -Destination (Join-Path $remoteToolsUNC $file) -Force
          $remoteExe = Join-Path $RemoteWorkDir $file
        } else {
          $remoteExe = $NetworkScannerPath
          # Vérifie que la cible voit bien le partage (sinon stoppe proprement)
          try {
            $sTest = New-PSSession -ComputerName $comp -ErrorAction Stop
            $canSee = Invoke-Command -Session $sTest -ScriptBlock { param($p) Test-Path $p } -ArgumentList $NetworkScannerPath
            Remove-PSSession $sTest -ErrorAction SilentlyContinue
            if (-not $canSee) { throw "UNC inaccessible depuis la cible (double-hop/ACL). Utilise -ScannerPath." }
          } catch { throw $_ }
        }

        try {
          $s = New-PSSession -ComputerName $comp -ErrorAction Stop
          try {
            $usedWinRM = $true
            $sb = {
              param($exe,$timeout)
              if (-not (Test-Path $exe)) { throw "Scanner introuvable: $exe" }
              $script = {
                param($e)
                $o = & $e 2>&1 | Out-String
                $ec = $LASTEXITCODE
                [pscustomobject]@{ ExitCode=$ec; Output=$o }
              }
              $j = Start-Job -ScriptBlock $script -ArgumentList $exe
              if (-not (Wait-Job -Job $j -Timeout $timeout)) { Stop-Job $j -Force; Remove-Job $j -Force; throw "Timeout après $timeout s." }
              $r = Receive-Job $j; Remove-Job $j -Force
              [pscustomobject]@{ ExitCode=$r.ExitCode; StdOut=$r.Output; StdErr='' }
            }
            $r = Invoke-Command -Session $s -ScriptBlock $sb -ArgumentList $remoteExe, $TimeOutSec -ErrorAction Stop
            $rawOut = ($r.StdOut + "`n" + $r.StdErr).Trim(); $exitCode=$r.ExitCode
          } finally { if ($s) { Remove-PSSession $s -ErrorAction SilentlyContinue } }
        } catch {
          # Fallback WMI (pas d’UNC)
          $logLocal = Join-Path $logsLocal 'hvci_scan.txt'
          if (-not $ScannerPath) { throw "WMI fallback ne peut pas exécuter un UNC (LocalSystem sans accès réseau). Utilise -ScannerPath." }
          $null = Invoke-CimMethod -ComputerName $comp -ClassName Win32_Process -MethodName Create -Arguments @{
            CommandLine = "cmd /c `"$remoteExe`" > `"$logLocal`" 2>&1"
          } -ErrorAction Stop
          $deadline = (Get-Date).AddSeconds($TimeOutSec); $ok=$false
          while ((Get-Date) -lt $deadline) { Start-Sleep 2; if (Test-Path (Join-Path $remoteLogsUNC 'hvci_scan.txt')) { $ok=$true; break } }
          if ($ok) { $rawOut = Get-Content (Join-Path $remoteLogsUNC 'hvci_scan.txt') -Raw } else { throw "Pas de sortie HVCI (WMI)." }
          $exitCode = 0
        }

        # Parsing + verdict
        $p = Parse-LocalHvciScanText -Text $rawOut; $drv=$p.Drivers; $inf=$p.Infs
        if ($rawOut -match 'VbsGetIssues:\s*(0x[0-9A-Fa-f]+)') { $issuesHex = $matches[1] }
        if ($rawOut -match 'VbsIsRecommended:\s*(\d+)')        { $vbsRec    = [int]$matches[1] }
        $issuesFlags = Get-PreScanIssuesFlags -Text $rawOut

        if ($rawOut -match '(?i)HVCI incompatible driver scan passed') { $hvciPassed = $true }
        elseif (($issuesHex -eq '0x00000000') -and ($drv.Count -eq 0) -and ($inf.Count -eq 0) -and ($exitCode -ge 0)) { $hvciPassed = $true }
        elseif (($drv.Count + $inf.Count) -gt 0) { $hvciPassed = $false }

        if ($hvciPassed -eq $true)      { $hvciMsg = 'HVCI incompatible driver scan passed!' }
        elseif ($hvciPassed -eq $false) { $hvciMsg = "HVCI scan: incompatibilités détectées (Drivers=$($drv.Count), INFs=$($inf.Count))" }
        else                            { $hvciMsg = 'HVCI scan: indéterminé (aucune sortie ou exécution incomplète)' }

        if ($ScannerPath -and -not $KeepRemoteCopy) { try { Remove-Item (Join-Path $remoteToolsUNC (Split-Path $ScannerPath -Leaf)) -Force } catch {} }
      }
      catch {
        $errText  = $_.Exception.Message
        if ([string]::IsNullOrWhiteSpace($rawOut)) { $rawOut = $errText }
        if ($null -eq $exitCode) { $exitCode = -1 }
        if (-not $hvciMsg) { $hvciMsg = 'HVCI scan: erreur' }
      }

      [pscustomobject]@{
        ComputerName        = $comp
        Reachable           = $reachable
        UsedWinRM           = $usedWinRM
        ExitCode            = $exitCode
        HvciPassed          = $hvciPassed
        HvciMessage         = $hvciMsg
        IssuesHex           = $issuesHex
        IssuesFlags         = $issuesFlags
        VbsIsRecommended    = $vbsRec
        IncompatibleDrivers = ($drv -join '; ')
        IncompatibleInfs    = ($inf -join '; ')
        RemoteExe           = $remoteExe
        RawOutput           = $rawOut
        Error               = $errText
        ScanTimeUtc         = [DateTime]::UtcNow
      }
    } -ThrottleLimit $MaxConcurrency
  }
  else {
    Write-Host "PS5 détecté → exécution via jobs (max $MaxConcurrency simultanés)..." -ForegroundColor Yellow
    $jobs = @()
    foreach ($c in $ComputerName) {
      while (($jobs | Where-Object State -eq 'Running').Count -ge $MaxConcurrency) {
        Start-Sleep 1
        $done = $jobs | Where-Object State -ne 'Running'
        foreach ($j in $done) { $results += Receive-Job $j; Remove-Job $j -Force; $jobs = $jobs | Where-Object Id -ne $j.Id }
      }
      $jobs += Start-Job -ScriptBlock $ps5Worker -ArgumentList $c, $ScannerPath, $NetworkScannerPath, $TimeOutSec, $RemoteWorkDir, [bool]$KeepRemoteCopy
    }
    Wait-Job $jobs | Out-Null
    foreach ($j in $jobs) { $results += Receive-Job $j; Remove-Job $j -Force }
  }
}
catch {
  Write-Warning "Une erreur est survenue pendant l'exécution: $($_.Exception.Message)"
}

# ------------------- Export CSV (FR) — toujours écrire un fichier (avec BOM)
$dur = (Get-Date) - $ts
$sep = [System.Globalization.CultureInfo]::CurrentCulture.TextInfo.ListSeparator
$OutputCsvFull = [System.IO.Path]::GetFullPath($OutputCsv)

# Sélection finale (et aplanir RawOutput si demandé)
$export = $results
if ($IncludeRawOutput) {
  $export = $export | ForEach-Object { $_.RawOutput = ($_.RawOutput -replace '(\r?\n)+',' ⏎ '); $_ }
} else {
  $export = $export | Select-Object ComputerName,Reachable,UsedWinRM,ExitCode,
    HvciPassed,HvciMessage,IssuesHex,IssuesFlags,VbsIsRecommended,
    IncompatibleDrivers,IncompatibleInfs,RemoteExe,Error,ScanTimeUtc
}

# Écrire le fichier quoi qu'il arrive
if (-not $export -or ($export | Measure-Object).Count -eq 0) {
  # En-têtes seuls, encodage UTF-8 BOM explicite
  $headers = @('ComputerName','Reachable','UsedWinRM','ExitCode',
               'HvciPassed','HvciMessage','IssuesHex','IssuesFlags','VbsIsRecommended',
               'IncompatibleDrivers','IncompatibleInfs','RemoteExe','Error','ScanTimeUtc')
  $headerLine = ($headers -join $sep) + "`r`n"
  $utf8bom = New-Object System.Text.UTF8Encoding($true)
  [System.IO.File]::WriteAllText($OutputCsvFull, $headerLine, $utf8bom)
}
else {
  $export | Export-Csv -Path $OutputCsvFull -NoTypeInformation -Encoding utf8BOM -UseCulture -Force
}

Write-Host ("Terminé: {0} hôtes, CSV: {1} (durée {2:mm\:ss})" -f ($results.Count), $OutputCsvFull, $dur) -ForegroundColor Green
