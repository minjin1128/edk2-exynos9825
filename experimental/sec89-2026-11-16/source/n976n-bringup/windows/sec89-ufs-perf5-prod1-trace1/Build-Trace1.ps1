# SEC89 UFS PERF5 PROD1 TRACE1 persistent Storport session, test-signed ARM64 driver. PowerShell 5.1.
[CmdletBinding()]
param(
    [string]$SourceDirectory = $PSScriptRoot,
    [Parameter(Mandatory = $true)][string]$OutputDirectory,
    [Parameter(Mandatory = $true)][string]$SigningDirectory,
    [ValidatePattern('^10\.0\.[0-9]+\.0$')][string]$KitVersion = '10.0.28000.0'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$started = [DateTime]::UtcNow
$whole = [Diagnostics.Stopwatch]::StartNew()
$steps = New-Object System.Collections.ArrayList
$inputs = @()
$artifacts = @()
$tools = [ordered]@{}
$peChecks = @()
$signatureChecks = @()
$passed = $false
$global:Sec89Perf5NativeRetired = $true
$failure = $null
$systemGeometry = @{ PARTITION_START=$null; PARTITION_BLOCKS=$null; VOLUME_BLOCKS=$null; VOLUME_BYTES=$null }
$geometry = @{ PARTITION_START_LBA=$null; PARTITION_BLOCKS=$null; IMAGE_BLOCKS=$null; BLOCK_BYTES=$null; IMAGE_BYTES=$null }
$oldTemp = $env:TEMP
$oldTmp = $env:TMP
$oldVsLang = $env:VSLANG
$env:VSLANG = '1033'
$source = [IO.Path]::GetFullPath($SourceDirectory).TrimEnd('\')
$output = [IO.Path]::GetFullPath($OutputDirectory).TrimEnd('\')
if (!(Test-Path -LiteralPath $source -PathType Container)) { throw 'SourceDirectory is missing.' }
if (Test-Path -LiteralPath $output) { throw 'OutputDirectory must be a new path; existing evidence is never overwritten.' }
if ($output.Equals($source, [StringComparison]::OrdinalIgnoreCase) -or
    $output.StartsWith($source + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'OutputDirectory must be outside SourceDirectory.'
}
[void][IO.Directory]::CreateDirectory($output)
$stage = Join-Path $output 'source'
$build = Join-Path $output 'build'
$package = Join-Path $output 'package'
$logs = Join-Path $output 'logs'
foreach ($dir in @($stage, $build, $package, $logs, (Join-Path $output 'tmp'))) {
    [void][IO.Directory]::CreateDirectory($dir)
}
$env:TEMP = Join-Path $output 'tmp'
$env:TMP = $env:TEMP

function Quote-NativeArgument([string]$Value) {
    # CommandLineToArgvW/CRT escaping, including a quoted path's trailing slash.
    $escaped = [regex]::Replace($Value, '(\\*)"', '$1$1\"')
    $escaped = [regex]::Replace($escaped, '(\\+)$', '$1$1')
    return '"' + $escaped + '"'
}
function Run-OwnedProcess([string]$Name, [string]$File, [string[]]$Arguments, [int]$DeadlineMilliseconds=300000) {
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
    $global:Sec89Perf5NativeRetired = $false
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
                $global:Sec89Perf5NativeRetired = $true
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
                $global:Sec89Perf5NativeRetired = $parentExited -and $streamsClosed -and
                    (!$killRequired -or $killSucceeded)
            }
        }
        catch {
            $global:Sec89Perf5NativeRetired = $false
            $runFailure = 'Process retirement was not confirmed: ' + $_.Exception.Message
        }
        $clock.Stop()
        [IO.File]::WriteAllText((Join-Path $logs ($Name + '.stdout.log')), $stdout)
        [IO.File]::WriteAllText((Join-Path $logs ($Name + '.stderr.log')), $stderr)
        [void]$steps.Add([ordered]@{ name=$Name; executable=$File; arguments=$Arguments;
            pid=$ownedPid; exit_code=$exitCode; timed_out=$timedOut; deadline_seconds=($DeadlineMilliseconds/1000);
            owned_tree_kill_required=$killRequired; taskkill_exit_code=$killExit;
            parent_exited=$parentExited; streams_closed=$streamsClosed;
            native_processes_retired=$global:Sec89Perf5NativeRetired;
            elapsed_seconds=$clock.Elapsed.TotalSeconds })
        $process.Dispose()
    }
    if (!$global:Sec89Perf5NativeRetired) { throw "$Name retirement is unconfirmed; preserve the RAM share and scratch." }
    if ($runFailure) { throw $runFailure }
    if ($exitCode -ne 0) { throw "$Name failed with exit code $exitCode. See logs." }
}
function File-Identity([string]$File) {
    $item = Get-Item -LiteralPath $File
    return [ordered]@{ path=$item.FullName; bytes=$item.Length;
        sha256=(Get-FileHash -LiteralPath $File -Algorithm SHA256).Hash.ToLowerInvariant();
        file_version=$item.VersionInfo.FileVersion }
}
function Inspect-Pe([string]$File, [bool]$RequireCfg) {
    $bytes = [IO.File]::ReadAllBytes($File)
    if ($bytes.Length -lt 64 -or [BitConverter]::ToUInt16($bytes,0) -ne 0x5A4D) { throw 'Invalid DOS header.' }
    $pe = [BitConverter]::ToInt32($bytes,0x3C)
    if ($pe -lt 0 -or $pe -gt $bytes.Length-24 -or [BitConverter]::ToUInt32($bytes,$pe) -ne 0x4550) { throw 'Invalid PE header.' }
    $machine = [BitConverter]::ToUInt16($bytes,$pe+4)
    $count = [BitConverter]::ToUInt16($bytes,$pe+6)
    $optionalSize = [BitConverter]::ToUInt16($bytes,$pe+20)
    $optional = $pe+24
    if ($machine -ne 0xAA64 -or $optionalSize -lt 112 -or $optional -gt $bytes.Length-$optionalSize -or
        [BitConverter]::ToUInt16($bytes,$optional) -ne 0x20B) { throw 'Expected bounded native ARM64 PE32+ image.' }
    $flags = [BitConverter]::ToUInt16($bytes,$optional+70)
    $nx = ($flags -band 0x100) -ne 0
    $dynamicBase = ($flags -band 0x40) -ne 0
    $cfg = ($flags -band 0x4000) -ne 0
    if (!$nx -or !$dynamicBase -or ($RequireCfg -and !$cfg)) { throw 'Required NX/DynamicBase/CFG image flags are missing.' }
    $table = $optional+$optionalSize
    if ($count -eq 0 -or $table -gt $bytes.Length-40*$count) { throw 'Invalid PE section table.' }
    $sections = @()
    for ($i=0; $i -lt $count; $i++) {
        $at = $table+40*$i
        $characteristics = [BitConverter]::ToUInt32($bytes,$at+36)
        $execute = ($characteristics -band 0x20000000) -ne 0
        $write = ($characteristics -band 0x80000000L) -ne 0
        if ($execute -and $write) { throw 'Executable writable PE section rejected.' }
        $sections += [ordered]@{ name=[Text.Encoding]::ASCII.GetString($bytes,$at,8).TrimEnd([char]0);
            characteristics=('0x{0:X8}' -f $characteristics); executable=$execute; writable=$write }
    }
    return [ordered]@{ file=$File; machine='ARM64/0xAA64'; native_arm64=$true; nx=$nx;
        dynamic_base=$dynamicBase; guard_cf=$cfg; no_executable_writable_sections=$true; sections=$sections }
}
try {
    # Stage a small source tree into owned scratch; WDK stamping cannot edit originals.
    foreach ($item in (Get-ChildItem -LiteralPath $source -Recurse -Force)) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Source reparse points are not accepted.' }
        if (!$item.PSIsContainer) {
            $relative = $item.FullName.Substring($source.Length+1)
            $destination = Join-Path $stage $relative
            [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($destination))
            Copy-Item -LiteralPath $item.FullName -Destination $destination
            $inputs += [ordered]@{ relative_path=$relative; bytes=$item.Length;
                sha256=(Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant() }
        }
    }
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (!(Test-Path -LiteralPath $vswhere)) { throw 'vswhere.exe is required to locate the installed toolchain.' }
    Run-OwnedProcess 'tool-discovery' $vswhere @('-latest','-products','*','-requires','Microsoft.Component.MSBuild','-property','installationPath')
    $vs = Get-Content -LiteralPath (Join-Path $logs 'tool-discovery.stdout.log') -Encoding UTF8 | Select-Object -First 1
    if ([string]::IsNullOrWhiteSpace($vs)) { throw 'No Visual Studio installation with MSBuild found.' }
    $vs = $vs.Trim()
    $msbuild = Join-Path $vs 'MSBuild\Current\Bin\arm64\MSBuild.exe'
    if (!(Test-Path -LiteralPath $msbuild)) { $msbuild = Join-Path $vs 'MSBuild\Current\Bin\MSBuild.exe' }
    if (!(Test-Path -LiteralPath $msbuild)) { throw 'MSBuild is unavailable.' }
    $msvcRoot = Join-Path $vs 'VC\Tools\MSVC'
    $msvc = Get-ChildItem -LiteralPath $msvcRoot -Directory | Sort-Object { [version]$_.Name } -Descending | Select-Object -First 1
    if ($null -eq $msvc) { throw 'MSVC tools are unavailable.' }
    $compiler = Join-Path $msvc.FullName 'bin\Hostarm64\arm64\cl.exe'
    if (!(Test-Path -LiteralPath $compiler)) { throw 'Native ARM64 compiler is unavailable.' }
    $kitRoot = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots' -Name KitsRoot10).KitsRoot10
    $infverif = $null
    $inf2cat = $null
    foreach ($arch in @('arm64','x64','x86')) {
        $candidate = Join-Path $kitRoot ('Tools\'+$KitVersion+'\'+$arch+'\InfVerif.exe')
        if (!$infverif -and (Test-Path -LiteralPath $candidate)) { $infverif=$candidate }
        $candidate = Join-Path $kitRoot ('bin\'+$KitVersion+'\'+$arch+'\Inf2Cat.exe')
        if (!$inf2cat -and (Test-Path -LiteralPath $candidate)) { $inf2cat=$candidate }
    }
    if (!$infverif -or !$inf2cat) { throw 'Matching WDK InfVerif/Inf2Cat tools are missing.' }
    $systemHeader = Get-Content -LiteralPath (Join-Path $stage 'N976nUfsSystem.h') -Raw
    foreach ($field in @('PARTITION_START','PARTITION_BLOCKS','VOLUME_BLOCKS','VOLUME_BYTES')) {
        $match = [regex]::Match($systemHeader, '(?m)^#define NUF_SYSTEM_'+$field+' (0x[0-9A-Fa-f]+)ULL\s*$')
        if (!$match.Success) { throw ('Missing SYSTEM geometry: '+$field) }
        $systemGeometry[$field] = [Convert]::ToUInt64($match.Groups[1].Value.Substring(2),16)
    }
    $tools = [ordered]@{ visual_studio=$vs; kit_root=$kitRoot; kit_version=$KitVersion;
        msvc_version=$msvc.Name; powershell=$PSVersionTable.PSVersion.ToString();
        process_architecture=$env:PROCESSOR_ARCHITECTURE;
        msbuild=(File-Identity $msbuild); compiler=(File-Identity $compiler);
        infverif=(File-Identity $infverif); inf2cat=(File-Identity $inf2cat) }
    # Read the generated image contract for reporting; never duplicate a numeric
    # write fence here. The compiler and offline-image binding validate it too.
    $header = [IO.File]::ReadAllText((Join-Path $stage 'N976nUfsNtfsExpected.h'))
    foreach ($field in @('PARTITION_START_LBA','PARTITION_BLOCKS','IMAGE_BLOCKS','BLOCK_BYTES','IMAGE_BYTES')) {
        $match = [regex]::Match($header, '(?m)^#define NUF_NTFS_'+$field+' (0x[0-9A-Fa-f]+)ULL\s*$')
        if (!$match.Success) { throw ('Missing generated NTFS geometry: '+$field) }
        $geometry[$field] = [Convert]::ToUInt64($match.Groups[1].Value.Substring(2),16)
    }
    $project = Join-Path $stage 'N976nUfs.vcxproj'
    $outDir = $build+'\'
    $intDir = (Join-Path $output 'obj')+'\'
    $assembler = Join-Path $msvc.FullName 'bin\Hostarm64\arm64\armasm64.exe'
    if (!(Test-Path -LiteralPath $assembler)) { throw 'Native ARM64 assembler is unavailable.' }
    $tools['assembler'] = File-Identity $assembler
    # Retain this small object so its instruction bytes can be compared with
    # the locally executed leaf routines and the final linked SYS.
    $ncObject = Join-Path $output 'N976nNcRanges.obj'
    Run-OwnedProcess 'nc-assemble' $assembler @('-nologo','-o',$ncObject,(Join-Path $stage 'N976nNcRanges.asm'))
    $buildArgs = @($project,'/t:Rebuild','/p:Configuration=Release','/p:Platform=ARM64',
        ('/p:NufNcObject='+$ncObject),'/p:SignMode=Off',('/p:WindowsTargetPlatformVersion='+$KitVersion),
        ('/p:VCToolsVersion='+$msvc.Name),('/p:OutDir='+$outDir),('/p:IntDir='+$intDir),
        '/m:1','/nr:false','/p:BuildInParallel=false','/nologo','/v:normal',
        ('/flp:LogFile='+(Join-Path $logs 'driver-msbuild.log')+';Verbosity=Detailed;Encoding=UTF-8'))
    Run-OwnedProcess 'driver-build' $msbuild $buildArgs
    $sys = Join-Path $build 'N976nUfs.sys'
    if (!(Test-Path -LiteralPath $sys -PathType Leaf)) { throw 'Expected ARM64 SYS was not generated.' }
    $peChecks += Inspect-Pe $sys $true
    Copy-Item -LiteralPath $sys -Destination $package
    Copy-Item -LiteralPath (Join-Path $stage 'N976nUfs.inf') -Destination $package
    $inf = Join-Path $package 'N976nUfs.inf'
    $signtool = Join-Path $kitRoot ('bin\'+$KitVersion+'\arm64\signtool.exe')
    if (!(Test-Path -LiteralPath $signtool)) { throw 'ARM64 SignTool missing' }
    $pfx = Join-Path $SigningDirectory 'N976nUfsTest.pfx'
    $cer = Join-Path $SigningDirectory 'N976nUfsTest.cer'
    $signer = New-Object Security.Cryptography.X509Certificates.X509Certificate2($cer)
    # The PFX is an ephemeral RAM-only task signing key, never installed/trusted.
    Run-OwnedProcess 'sign-sys' $signtool @('sign','/fd','SHA256','/f',$pfx,(Join-Path $package 'N976nUfs.sys'))
    Run-OwnedProcess 'inf-verification' $infverif @('/w',$inf)
    Run-OwnedProcess 'catalog' $inf2cat @(('/driver:'+$package),'/os:10_VB_ARM64','/uselocaltime')
    $cat = Join-Path $package 'N976nUfs.cat'
    if (!(Test-Path -LiteralPath $cat -PathType Leaf)) { throw 'Catalog was not generated.' }
    Run-OwnedProcess 'sign-cat' $signtool @('sign','/fd','SHA256','/f',$pfx,$cat)
    Copy-Item -LiteralPath $cer -Destination $package
    Copy-Item -LiteralPath (Join-Path $SigningDirectory 'N976nUfsTest.pem') -Destination $package
    foreach ($signedFile in @((Join-Path $package 'N976nUfs.sys'),$cat)) {
        $signature = Get-AuthenticodeSignature -LiteralPath $signedFile
        $signatureChecks += [ordered]@{ file=$signedFile; status=$signature.Status.ToString();
            signer_present=($null -ne $signature.SignerCertificate);
            signer_thumbprint=$signature.SignerCertificate.Thumbprint }
        if ($null -eq $signature.SignerCertificate -or
            $signature.SignerCertificate.Thumbprint -ne $signer.Thumbprint -or
            $signature.Status.ToString() -notin @('Valid','UnknownError','NotTrusted')) {
            throw 'Signed file certificate mismatch or signature/hash failure.'
        }
    }
    $files = @(Get-ChildItem -LiteralPath $package -File | ForEach-Object {
        [ordered]@{ name=$_.Name; bytes=$_.Length; sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() }
    })
    [ordered]@{ signed=$true; signer_thumbprint=$signer.Thumbprint; files=$files;
        independent_signature_verification_required=$true; vm_trust_changed=$false
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $package 'signing-manifest.json') -Encoding UTF8
    foreach ($item in (Get-ChildItem -LiteralPath $package -File)) { $artifacts += File-Identity $item.FullName }
    $passed=$true
}
catch { $failure=$_.Exception.Message }
finally {
    $whole.Stop()
    $env:TEMP=$oldTemp
    $env:TMP=$oldTmp
    $env:VSLANG=$oldVsLang
    $report=[ordered]@{ schema=1; milestone='SEC89 UFS PERF5 PROD1 TRACE1'; classification='test_signed_persistent_ufs_session';
        passed=$passed; failure=$failure; started_utc=$started.ToString('o'); completed_utc=[DateTime]::UtcNow.ToString('o');
        elapsed_seconds=$whole.Elapsed.TotalSeconds; source_directory=$source; output_directory=$output;
        tools=$tools; source_inputs=$inputs; steps=@($steps); compiler_command_log='logs/driver-msbuild.log'; pe_checks=$peChecks; signature_checks=$signatureChecks; artifacts=$artifacts;
        hardware_verified=$false; installed=$false; signed=($passed -and $signatureChecks.Count -eq 2); wim_modified=$false; partition_writes=$false;
        diagnostic_stop=[ordered]@{enabled=$false;operational_driver=$true;crash_dump_supported=$false};
        preserved_backend_geometry=[ordered]@{mode='read-exact-system-esp-fat-prefix-and-userdata-ntfs-writes-device-flush';lun=0;partition_start_lba=$geometry.PARTITION_START_LBA;partition_blocks=$geometry.PARTITION_BLOCKS;write_blocks=$geometry.IMAGE_BLOCKS;block_bytes=$geometry.BLOCK_BYTES;write_bytes=$geometry.IMAGE_BYTES;outside_range_writes=$false;standard_write_path=$true;write_through=$false;write_cache_enabled=$true;fua_one_final_flush=$true;per_write_readback=$false;runtime_formatting=$false};
        system_esp_geometry=[ordered]@{partition_start_lba=$systemGeometry.PARTITION_START;partition_blocks=$systemGeometry.PARTITION_BLOCKS;write_blocks=$systemGeometry.VOLUME_BLOCKS;write_bytes=$systemGeometry.VOLUME_BYTES;scope_report_version=3;semantic_primary_backup_bpb=$true;gpt_writes=$false};
        api_validation_disabled=$false; native_processes_retired=$global:Sec89Perf5NativeRetired; comprehensive_regression_performed=$false;
        omissions=@('No physical full Windows boot verification; no intentional diagnostic stop',
            'No crash-dump stack support or guarantee of visible bugcheck',
            'No physical UFS, MMIO or firmware handoff execution',
            'No driver installation or physical Windows storage verification',
            'Independent package signature verification required before deployment',
            'No comprehensive platform regression') }
    $report | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $output 'sec89-perf5-prod1-trace1-build.json') -Encoding UTF8
}
if (!$passed) { throw "SEC89 UFS PERF5 PROD1 TRACE1 build failed: $failure" }
Write-Output ('SEC89 UFS PERF5 PROD1 TRACE1 persistent Storport package prepared: '+$package)
