param([Parameter(Mandatory=$true)][string]$SourceDirectory,
      [Parameter(Mandatory=$true)][string]$OutputDirectory)
$ErrorActionPreference='Stop'
$original=[IO.File]::ReadAllText((Join-Path $SourceDirectory 'startup\Start-Demo.cmd'))
$rows=@()
foreach($case in @('missing','returned')) {
    $root=Join-Path $OutputDirectory ('fallback-'+$case)
    [void][IO.Directory]::CreateDirectory($root)
    $batch=Join-Path $root 'Start-Demo.cmd'
    $text=$original.Replace('X:\N976nTouchDemo',$root)
    $expected=2
    if($case -eq 'returned') {
        [IO.File]::WriteAllText((Join-Path $root 'N976nTouchDemo.exe'),'fixture existence sentinel; never executed')
        $old='start "" /wait "'+$root+'\N976nTouchDemo.exe" --pe-start'
        if(!$text.Contains($old)){throw 'Actual launch line not found'}
        # Exercise the real batch wait/errorlevel flow with a harmless child.
        $text=$text.Replace($old,'start "" /wait "%SystemRoot%\System32\cmd.exe" /d /c exit 37')
        $expected=37
    }
    [IO.File]::WriteAllText($batch,$text,[Text.Encoding]::ASCII)
    $si=New-Object Diagnostics.ProcessStartInfo
    $si.FileName=Join-Path $env:SystemRoot 'System32\cmd.exe'
    $si.Arguments='/d /q /k ""'+$batch+'""'
    $si.UseShellExecute=$false;$si.CreateNoWindow=$true
    $si.RedirectStandardInput=$true;$si.RedirectStandardOutput=$true;$si.RedirectStandardError=$true
    $p=New-Object Diagnostics.Process;$p.StartInfo=$si
    try {
        if(!$p.Start()){throw 'Cannot start owned fallback fixture'}
        $o=$p.StandardOutput.ReadToEndAsync();$e=$p.StandardError.ReadToEndAsync()
        if($p.WaitForExit(1500)){throw 'Fallback CMD closed instead of retaining its prompt'}
        $p.StandardInput.WriteLine('exit 0');$p.StandardInput.Close()
        if(!$p.WaitForExit(5000)){throw 'Owned fallback CMD did not retire'}
        if(!$o.Wait(1000) -or !$e.Wait(1000)){throw 'Fallback output streams did not retire'}
        $output=$o.Result+$e.Result
        [IO.File]::WriteAllText((Join-Path $root 'console.txt'),$output)
        if(!$output.Contains('[Stage 0]') -or !$output.Contains('Native demo returned: '+$expected) -or
           !$output.Contains('This prompt remains available.')) {throw 'Required fallback output missing'}
        $rows += [ordered]@{case=$case;expected_exit=$expected;stage0=$true;error_preserved=$true;prompt_survived=$true;owned_process_retired=$true}
    } finally {
        if(!$p.HasExited){$p.Kill();if(!$p.WaitForExit(5000)){throw 'Fallback process retirement failed'}}
        $p.Dispose()
    }
}
[ordered]@{passed=$true;checks=$rows;scope='Actual CMD fallback with RAM path substitution and harmless return-code child; no PE/system mutation'} |
    ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'fallback-cmd-tests.json') -Encoding UTF8
Write-Output 'PASS 2 CMD fallback cases'
