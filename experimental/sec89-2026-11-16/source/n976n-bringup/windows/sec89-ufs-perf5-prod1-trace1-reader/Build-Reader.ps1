# SPDX-License-Identifier: MIT
# Managed-RAM ARM64 console build; no driver, certificate, installation or policy changes.
# Native child retirement helper reused from the project's Build-Sec76.ps1.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$SourceDirectory,
      [Parameter(Mandatory=$true)][string]$OutputDirectory,
      [Parameter(Mandatory=$true)][string]$FixtureDirectory)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$global:SnapshotNativeRetired=$true
$output=[IO.Path]::GetFullPath($OutputDirectory).TrimEnd('\')
if(Test-Path -LiteralPath $output){throw 'Output must be new'}
[void][IO.Directory]::CreateDirectory($output)
$logs=Join-Path $output 'logs'
[void][IO.Directory]::CreateDirectory($logs)
$steps=New-Object System.Collections.ArrayList
$oldTemp=$env:TEMP;$oldTmp=$env:TMP;$oldLang=$env:VSLANG
$env:TEMP=Join-Path $output 'tmp';$env:TMP=$env:TEMP;$env:VSLANG='1033'
[void][IO.Directory]::CreateDirectory($env:TEMP)
$receipt=[ordered]@{passed=$false;phone_access=$false;installed=$false;signed=$false;policy_changed=$false;steps=$steps}
function Quote-NativeArgument([string]$Value) {
    # CommandLineToArgvW/CRT escaping, including a quoted path's trailing slash.
    $escaped = [regex]::Replace($Value, '(\\*)"', '$1$1\"')
    $escaped = [regex]::Replace($escaped, '(\\+)$', '$1$1')
    return '"' + $escaped + '"'
}
function Run-OwnedProcess([string]$Name, [string]$File, [string[]]$Arguments, [int]$DeadlineMilliseconds=300000, [int]$ExpectedExit=0) {
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = $File
    $info.Arguments = (($Arguments | ForEach-Object { Quote-NativeArgument $_ }) -join ' ')
    $info.WorkingDirectory = $output
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $info
    $timedOut = $false
    $exitCode = $null
    $ownedPid = $null
    $outTask = $null
    $errTask = $null
    $stdout = ''
    $stderr = ''
    $killExit = $null
    $runFailure = $null
    $parentExited = $false
    $streamsClosed = $false
    $killRequired = $false
    $killSucceeded = $false
    $global:SnapshotNativeRetired = $false
    try {
        if (!$process.Start()) { throw "Cannot start $Name" }
        $ownedPid = $process.Id
        $outTask = $process.StandardOutput.ReadToEndAsync()
        $errTask = $process.StandardError.ReadToEndAsync()
        if (!$process.WaitForExit($DeadlineMilliseconds)) {
            $timedOut = $true
            $killRequired = $true
            throw "$Name exceeded its bounded deadline."
        }
    }
    catch { $runFailure = $_.Exception.Message }
    finally {
        try {
            if ($null -eq $ownedPid) {
                # Start failed: no child was created by this invocation.
                $global:SnapshotNativeRetired = $true
            }
            else {
                if (!$process.HasExited) { $killRequired = $true }
                if ($killRequired) {
                    # Only the newly created PID and descendants; never an image-name kill.
                    $kill = New-Object Diagnostics.ProcessStartInfo
                    $kill.FileName = Join-Path $env:SystemRoot 'System32\taskkill.exe'
                    $kill.Arguments = '/PID ' + $ownedPid + ' /T /F'
                    $kill.UseShellExecute = $false
                    $kill.CreateNoWindow = $true
                    $killer = [Diagnostics.Process]::Start($kill)
                    try {
                        if ($killer.WaitForExit(15000)) {
                            $killExit = $killer.ExitCode
                            $killSucceeded = $killExit -eq 0
                        }
                        else {
                            $killer.Kill()
                            [void]$killer.WaitForExit(5000)
                        }
                    }
                    finally { $killer.Dispose() }
                }
                $parentExited = $process.WaitForExit(10000)
                if ($parentExited) { $exitCode = $process.ExitCode }
                if ($null -ne $outTask -and $null -ne $errTask) {
                    $outClosed = $outTask.Wait(5000)
                    $errClosed = $errTask.Wait(5000)
                    $streamsClosed = $outClosed -and $errClosed
                    if ($outClosed) { $stdout = $outTask.Result }
                    if ($errClosed) { $stderr = $errTask.Result }
                }
                $global:SnapshotNativeRetired = $parentExited -and $streamsClosed -and
                    (!$killRequired -or $killSucceeded)
            }
        }
        catch {
            $global:SnapshotNativeRetired = $false
            $runFailure = 'Process retirement was not confirmed: ' + $_.Exception.Message
        }
        $clock.Stop()
        [IO.File]::WriteAllText((Join-Path $logs ($Name + '.stdout.log')), $stdout)
        [IO.File]::WriteAllText((Join-Path $logs ($Name + '.stderr.log')), $stderr)
        [void]$steps.Add([ordered]@{ name=$Name; executable=$File; arguments=$Arguments;
            pid=$ownedPid; exit_code=$exitCode; timed_out=$timedOut; deadline_seconds=($DeadlineMilliseconds/1000);
            owned_tree_kill_required=$killRequired; taskkill_exit_code=$killExit;
            parent_exited=$parentExited; streams_closed=$streamsClosed;
            native_processes_retired=$global:SnapshotNativeRetired;
            elapsed_seconds=$clock.Elapsed.TotalSeconds })
        $process.Dispose()
    }
    if (!$global:SnapshotNativeRetired) { throw "$Name retirement is unconfirmed; preserve the RAM share and scratch." }
    if ($runFailure) { throw $runFailure }
    if ($exitCode -ne $ExpectedExit) { throw "$Name returned $exitCode; expected $ExpectedExit. See logs." }
}

try {
  $vswhere=Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
  Run-OwnedProcess 'discover-vs' $vswhere @('-latest','-products','*','-requires','Microsoft.Component.MSBuild','-property','installationPath') 30000
  $vs=[IO.File]::ReadAllText((Join-Path $logs 'discover-vs.stdout.log')).Trim()
  $msbuild=Join-Path $vs 'MSBuild\Current\Bin\arm64\MSBuild.exe'
  if(!(Test-Path -LiteralPath $msbuild)){throw 'Native ARM64 MSBuild required'}
  $bin=Join-Path $output 'bin';$obj=Join-Path $output 'obj'
  $project=Join-Path $SourceDirectory 'N976nUfsTrace.vcxproj'
  Run-OwnedProcess 'build-arm64' $msbuild @($project,'/nologo','/m:2','/t:Build','/p:Configuration=Release','/p:Platform=ARM64',('/p:OutDir='+$bin+'\'),('/p:IntDir='+$obj+'\')) 180000
  $exe=Join-Path $bin 'N976nUfsTrace.exe'
  $pe=[IO.File]::ReadAllBytes($exe)
  if($pe.Length -lt 64 -or [BitConverter]::ToUInt16($pe,0) -ne 0x5A4D){throw 'Bad DOS header'}
  $off=[BitConverter]::ToUInt32($pe,0x3C)
  if($off -gt $pe.Length-112 -or [BitConverter]::ToUInt32($pe,$off) -ne 0x4550){throw 'Bad PE offset'}
  $machine=[BitConverter]::ToUInt16($pe,$off+4)
  $magic=[BitConverter]::ToUInt16($pe,$off+24)
  $sub=[BitConverter]::ToUInt16($pe,$off+24+68)
  $flags=[BitConverter]::ToUInt16($pe,$off+24+70)
  if($machine -ne 0xAA64 -or $magic -ne 0x20B -or $sub -ne 3 -or ($flags -band 0x4140) -ne 0x4140){throw 'ARM64 console NX ASLR CFG requirements failed'}
  $receipt.pe=[ordered]@{machine=$machine;optional_magic=$magic;subsystem=$sub;dll_characteristics=$flags;NX=$true;ASLR=$true;CFG=$true}
  $receipt.exe=[ordered]@{bytes=$pe.Length;sha256=(Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()}
  foreach($name in @('before','after','clock-invalid')){
    Run-OwnedProcess ('show-'+$name) $exe @('show',(Join-Path $FixtureDirectory ($name+'.bin'))) 30000
  }
  Run-OwnedProcess 'diff-valid' $exe @('diff',(Join-Path $FixtureDirectory 'before.bin'),(Join-Path $FixtureDirectory 'after.bin')) 30000
  Run-OwnedProcess 'diff-reversed' $exe @('diff',(Join-Path $FixtureDirectory 'after.bin'),(Join-Path $FixtureDirectory 'before.bin')) 30000 2
  $bad=[IO.File]::ReadAllBytes((Join-Path $FixtureDirectory 'before.bin'))
  foreach($case in @(@('magic',0,0),@('generation',32,1),@('ring',184,0),@('flags',1724,0))){
    $copy=[byte[]]$bad.Clone();$copy[[int]$case[1]]=[byte]$case[2]
    $file=Join-Path $FixtureDirectory ('bad-'+$case[0]+'.bin');[IO.File]::WriteAllBytes($file,$copy)
    Run-OwnedProcess ('reject-'+$case[0]) $exe @('show',$file) 30000 2
  }
  Run-OwnedProcess 'usage' $exe @() 30000 2
  Run-OwnedProcess 'vm-no-adapter' $exe @('capture',(Join-Path $output 'must-not-exist.bin')) 30000 2
  if(Test-Path (Join-Path $output 'must-not-exist.bin')){throw 'VM discovery unexpectedly wrote output'}
  foreach($name in @('Read-Ufs-Trace.cmd','README.txt')){[IO.File]::Copy((Join-Path $SourceDirectory $name),(Join-Path $bin $name))}
  $receipt.passed=$true
} catch {
  $receipt.error=($_ | Out-String)
  throw
} finally {
  $receipt.native_retired=$global:SnapshotNativeRetired
  [IO.File]::WriteAllText((Join-Path $output 'build.json'),($receipt|ConvertTo-Json -Depth 12))
  $env:TEMP=$oldTemp;$env:TMP=$oldTmp;$env:VSLANG=$oldLang
}
