# HVCI (Memory Integrity) — AD Fleet Scanner

> **Script goal:** Scan a set of Windows machines (from AD or a given list) for **HVCI / Memory Integrity readiness** using a provided scanner executable/script.  
> **Engines:** PowerShell 7 ⇒ parallel (`ForEach-Object -Parallel`); PowerShell 5 ⇒ jobs.  
> **Output:** A CSV (UTF‑8 with BOM, culture separator) with normalized fields and an optional flattened raw output.

---

## ✅ Features

- Targets computers from **Active Directory** (OU + LDAP filter) or an explicit `-ComputerName` list.  
- Prefers **WinRM** for remote execution; automatic **WMI fallback** (`Win32_Process Create`) when WinRM is unavailable.  
- Handles **UNC double-hop** pitfalls (recommends local copy via `-ScannerPath`).  
- Extracts and summarizes **incompatible drivers (.sys)** and **INFs (.inf)**.  
- Captures `VbsGetIssues` → **IssuesHex** and gathers pre-scan hints → **IssuesFlags**.  
- Computes a verdict (**HvciPassed / HvciMessage**).  
- Writes a **culture-aware CSV** (Excel FR ready, UTF‑8 BOM + `-UseCulture`).  
- Optional **RawOutput** column (flattened) for forensics.

---

## 📦 Requirements / Prerequisites

- **Admin rights** on target machines (local Administrator or equivalent).  
- Network access to `\\<HOST>\C$` (admin shares) when copying tools or collecting logs.  
- **RSAT ActiveDirectory** module on the runner if you use AD discovery (i.e., when `-ComputerName` isn’t specified).  
- **WinRM** enabled on targets for PSSession (recommended). If not, the script tries **WMI fallback**.  
- The HVCI scanner binary/script must be provided via **`-ScannerPath`** (local copy recommended) or **`-NetworkScannerPath`** (UNC).

> ℹ️ WMI fallback **cannot execute a UNC path** (LocalSystem has no network token). If WinRM is not available and you plan to rely on fallback, **use `-ScannerPath`**.

---

## 🧮 Parameters

### Quick table

| Parameter | Type | Required | Default | Description |
|---|---|:---:|---|---|
| `ScannerPath` | `string` | No* | — | **Local** path to the HVCI scanner. The file is copied to the remote host and executed there. *Required if `NetworkScannerPath` is not set.* |
| `NetworkScannerPath` | `string` | No* | — | **UNC** path to the HVCI scanner that the target must be able to access directly. *Required if `ScannerPath` is not set.* |
| `OutputCsv` | `string` | **Yes** | — | Output CSV path (created if needed). |
| `OUDN` | `string` | No | AD root | Optional **OU DN** to limit AD discovery. Ignored if `ComputerName` is provided. |
| `Filter` | `string` | No | `(enabled -eq $true)` | AD `Get-ADComputer` filter. Only enabled machines are kept. |
| `ComputerName` | `string[]` | No | — | Explicit list of machines. When set, **AD discovery is skipped**. |
| `MaxConcurrency` | `int` | No | `24` | PS7: `ThrottleLimit` for parallel loop. PS5: maximum concurrent jobs. |
| `TimeOutSec` | `int` | No | `180` | Per‑host timeout for scanner execution / collection. |
| `RemoteWorkDir` | `string` | No | `C:\ProgramData\Audit\Tools\HVCI` | Remote working folder (auto‑created). |
| `KeepRemoteCopy` | `switch` | No | `False` | Keep the copied scanner on the target instead of removing it. |
| `IncludeRawOutput` | `switch` | No | `False` | Include flattened `RawOutput` column in the CSV (useful for forensics). |

### Behavior details

- **Target resolution**:  
  - If `-ComputerName` **not** set → AD discovery: `Get-ADComputer -Filter <Filter> -SearchBase <OUDN or root> | Where Enabled`.  
  - If AD finds nothing → continues with an **empty** list (CSV header still written).

- **Remote execution path**:  
  1) **WinRM PSSession** → run scanner, capture stdout/stderr and exit code.  
  2) **WMI fallback** (if WinRM fails): `Win32_Process Create "cmd /c <scanner> > <log> 2>&1"`, then poll for `\\<HOST>\C$\ProgramData\Audit\Logs\hvci_scan.txt`.  
     - Fallback requires `-ScannerPath` (no UNC).  
     - If neither WinRM nor WMI succeeds, a row with `Error`/`ExitCode=-1` is produced (or at least CSV header).

- **Copying the scanner**:  
  - With `-ScannerPath`, the file is copied to `\\<HOST>\C$\<RemoteWorkDir leaf>` and executed from `<RemoteWorkDir>\file`.  
  - With `-NetworkScannerPath`, the script attempts a quick **remote Test-Path** via PSSession to validate UNC reachability from the **target’s context** (double-hop/ACLs).

- **Parsing**:  
  - Collects `*.sys` and `*.inf` values found in output (deduped, case‑insensitive).  
  - Extracts `IssuesHex` from `VbsGetIssues: 0x...` (if present).  
  - Extracts `VbsIsRecommended` from `VbsIsRecommended: <0|1>`.  
  - `IssuesFlags` concatenates pre‑scan hints shown **before** the “HVCI incompatible driver scan start” line.  
  - Verdict:  
    - `HvciPassed = $true` if output contains `HVCI incompatible driver scan passed` **or** (`IssuesHex` = `0x00000000` **and** no drivers/INFs reported and non‑negative exit code).  
    - `HvciPassed = $false` if any driver/INF is reported.  
    - Otherwise **indeterminate** with a generic message.

---

## 📤 Output CSV

- **Encoding:** UTF‑8 with BOM (`-Encoding utf8BOM`)  
- **Separator:** **current culture** list separator (`-UseCulture`) → `;` on FR systems.  
- **Always produced:** If no results, a file with **headers only** is still written.

### Columns

| Column | Meaning |
|---|---|
| `ComputerName` | Target hostname. |
| `Reachable` | ICMP reachable before attempting remote execution. |
| `UsedWinRM` | `True` if the main execution path used a PSSession; `False` if WMI fallback was used (or neither). |
| `ExitCode` | Scanner’s exit code (or `-1` if execution failed before running it). |
| `HvciPassed` | Final boolean verdict (may be `$null` if indeterminate). |
| `HvciMessage` | Human‑readable status message. |
| `IssuesHex` | Raw `VbsGetIssues` bitmask (e.g., `0x00000000` means **no issue** as reported by the scanner). Interpretation depends on the scanner version. |
| `IssuesFlags` | Concatenation of pre‑scan hints shown before the incompatible driver scan begins. Useful context. |
| `VbsIsRecommended` | `0` or `1` as reported by the scanner. |
| `IncompatibleDrivers` | `; `‑separated `.sys` filenames found in output. |
| `IncompatibleInfs` | `; `‑separated `.inf` filenames found in output (e.g., `oem42.inf`). |
| `RemoteExe` | Path used on the remote host (local copy or UNC). |
| `RawOutput` | (Only if `-IncludeRawOutput`) Entire tool output flattened (line breaks replaced by `⏎`). |
| `Error` | Error text captured by the wrapper (if any). |
| `ScanTimeUtc` | Timestamp of the scan result row (UTC). |

> 🔍 **About `IssuesHex`**  
> This is the **raw bitmask** extracted from the scanner output line `VbsGetIssues: 0x########`. The exact bit meanings are **tool‑specific** (they can vary across Microsoft readiness tools/releases). Use `-IncludeRawOutput` to preserve the full text and correlate any hints/messages with this value.

---

## 🧪 Usage Examples

> Replace the placeholder scanner path with your actual HVCI readiness tool (EXE/CMD/PS1).

### 1) AD OU scope with local copy (recommended), include raw output
```powershell
.\Invoke-HvciScan.ps1 `
  -ScannerPath 'C:\Tools\Hvci\HvciScanner.exe' `
  -OutputCsv '\\SRV-FICHIERS\SecOps\Reports\HVCI_2025-10-30.csv' `
  -OUDN 'OU=Workstations,OU=Paris,DC=cmcap,DC=lan' `
  -Filter '(enabled -eq $true -and OperatingSystem -like ""*Windows*"" )' `
  -IncludeRawOutput
```

### 2) Using a UNC tool path (requires WinRM + target access to the share)
```powershell
.\Invoke-HvciScan.ps1 `
  -NetworkScannerPath '\\SRV-TOOLS\Audit$\Hvci\HvciScanner.exe' `
  -OutputCsv '\\SRV-FICHIERS\SecOps\Reports\HVCI_Paris.csv' `
  -OUDN 'OU=Servers,DC=cmcap,DC=lan'
# If the target cannot see the UNC (double-hop/ACL), the script will fail fast
# and suggest using -ScannerPath instead.
```

### 3) Explicit list of machines, smaller concurrency, longer timeout
```powershell
.\Invoke-HvciScan.ps1 `
  -ScannerPath 'C:\Tools\Hvci\HvciScanner.exe' `
  -ComputerName 'WS01','WS02','SRV-APP01' `
  -OutputCsv 'C:\Temp\HVCI_subset.csv' `
  -MaxConcurrency 8 -TimeOutSec 300
```

### 4) Post‑processing: list failures only
```powershell
$rows = Import-Csv 'C:\Temp\HVCI_subset.csv'
$rows | Where-Object { $_.HvciPassed -eq 'False' } |
  Select ComputerName, HvciMessage, IncompatibleDrivers, IncompatibleInfs |
  Sort-Object ComputerName | Format-Table -Auto
```

---

## 🔐 Notes & Good Practices

- Prefer `-ScannerPath` to **avoid double-hop** and permission issues.  
- Keep the default `RemoteWorkDir` under `ProgramData` (non-roaming, easy ACLs).  
- If you want to keep the binary on hosts for later re-scans, add **`-KeepRemoteCopy`**.  
- Ensure **antivirus exclusions** if your tool is frequently copied/executed to reduce friction.  
- If you need full forensics or vendor support, run with **`-IncludeRawOutput`** to preserve textual context.

---

## 🧰 Troubleshooting

- `UNC inaccessible depuis la cible ... Utilise -ScannerPath.` → The target session cannot reach the share. Copy locally instead.  
- `Hôte injoignable (ICMP).` → Ping blocked/unreachable; consider testing WinRM directly or ensure firewall rules.  
- No `hvci_scan.txt` materializes with WMI fallback → The process did not run or AV blocked it; verify `RemoteExe` path and AV logs.  
- CSV contains **only headers** → No targets or every attempt failed before producing rows. Check permissions and connectivity.  
- `ExitCode = -1` → Wrapper error before running the scanner (see `Error` and `RawOutput`).

---

## 📝 Change log

- **2025‑10‑30**: Initial public documentation for the AD fleet wrapper (PS7 parallel + PS5 jobs, UNC validation, WMI fallback, culture‑aware CSV).

---

## ⚖️ License

This documentation can be used freely with your script. If you plan to publish, consider adding a license (e.g., MIT) to your repository.
