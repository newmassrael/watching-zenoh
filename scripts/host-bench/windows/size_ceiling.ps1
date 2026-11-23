# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
<#
The size of the pico C ABI's release DLL against zenoh-pico on Windows (docs/upstream-parity.md D9):
the half of the reading only a Windows host can make, zenoh-pico built with MSVC as the plan says.
'pico_windows_package.py --size-plan' makes the plan from a package zip, and
'pico_windows_package.py --size-judge' grades what this leaves. It runs in Windows PowerShell 5.1 and
needs the MSVC toolchain and CMake; no Python and no Rust.

  size_ceiling.ps1 -Plan plan.json -PicoSource DIR|ZIP -Work DIR -Out DIR [-CMake cmake.exe]
                   [-Generator 'Visual Studio 17 2022']

The plan names the width (the compiler vcvarsall.bat sets up and CMake's platform), the switches
derived from the package's features, the other CMake arguments of the same build and its
configuration; nothing here restates them. -PicoSource is the pinned vendor/zenoh-pico, a directory
or an archive of it (git archive --prefix=zenoh-pico/), copied or unpacked into -Work before it is
configured, since pico's configure writes into its source tree.

-Out is left holding the reading: plan.json (the plan as it was given), zenohpico.dll (the
reference), config.h (the header pico generated, from which the judge reads a switch built otherwise
than asked) and reading.json (the toolchain, the date, and the CMake cache entries of pico's own
options and of the build's type and flags). Each run writes the four files over what was there.

Exit status: 0 when the reference was built and the reading written, 2 when an input is refused or
the build failed (the log is named).

A run by hand, from Linux in a checkout of the commit the package was built from, against a Windows
host reached over ssh (its shell cmd); the package is the package-windows artifact of that commit's
Platform run, the single library without std of the width (x86 alike, with its artifact):

  out=target/size-win; mkdir -p "$out"
  gh run download <platform run id> -n pico-windows-package-x64-single-nostd -D "$out"
  zip="$(ls "$out"/wz-capi-pico-*-windows-x64-*.zip)"
  python3 scripts/lib/pico_windows_package.py --size-plan "$zip" "$out/plan.json"
  git -C vendor/zenoh-pico archive --format=zip --prefix=zenoh-pico/ -o "$PWD/$out/zenoh-pico.zip" HEAD
  ssh pc3-win "if not exist C:\wzsize mkdir C:\wzsize"
  scp "$out/plan.json" "$out/zenoh-pico.zip" scripts/host-bench/windows/size_ceiling.ps1 pc3-win:C:/wzsize/
  ssh pc3-win "powershell -NoProfile -ExecutionPolicy Bypass -File C:\wzsize\size_ceiling.ps1 -Plan C:\wzsize\plan.json -PicoSource C:\wzsize\zenoh-pico.zip -Work C:\wzsize\work -Out C:\wzsize\reading"
  scp -r pc3-win:C:/wzsize/reading "$out/"
  python3 scripts/lib/pico_windows_package.py --size-judge "$zip" "$out/reading"

The judge holds the two DLLs to one linker: on a host whose link.exe is another version than the one
that linked the package, the reading is a finding and not a figure.
#>
[CmdletBinding()]
param(
    [string]$Plan = '',
    [string]$PicoSource = '',
    [string]$Work = '',
    [string]$Out = '',
    [string]$CMake = '',
    [string]$Generator = 'Visual Studio 17 2022'
)

$ErrorActionPreference = 'Stop'
# Windows PowerShell 5.1 writes an array that passed through a pipeline as {"value": [...], "Count": n} while
# the extended type data of System.Array is loaded; the reading is read by Python.
Remove-TypeData System.Array -ErrorAction SilentlyContinue
[System.Threading.Thread]::CurrentThread.CurrentCulture = [System.Globalization.CultureInfo]::InvariantCulture
$Utf8 = New-Object System.Text.UTF8Encoding $false
$CRLF = [string][char]13 + [string][char]10
$Q = '"'
$PlanSchema = 'wz-pico-size-windows-plan/1'
$ReadingSchema = 'wz-pico-size-windows-reading/1'

function Fail([string]$why) {
    [Console]::Out.WriteLine("pico-size-windows: REFUSED, $why")
    exit 2
}

function Say([string]$line) { [Console]::Out.WriteLine("pico-size-windows: $line") }

function Write-Text([string]$path, [string]$text) { [System.IO.File]::WriteAllText($path, $text, $Utf8) }

# A file another process may still hold open for writing.
function Read-Text([string]$path) {
    if (-not (Test-Path -LiteralPath $path)) { return '' }
    $stream = New-Object System.IO.FileStream($path, 'Open', 'Read', 'ReadWrite')
    try {
        $reader = New-Object System.IO.StreamReader($stream, $Utf8)
        return $reader.ReadToEnd()
    } finally {
        $stream.Dispose()
    }
}

function Reset-Directory([string]$path) {
    if (Test-Path -LiteralPath $path) { Remove-Item -Recurse -Force -LiteralPath $path }
    [void](New-Item -ItemType Directory -Path $path)
}

function Find-VsRoot {
    $vswhere = Join-Path ([Environment]::GetFolderPath('ProgramFilesX86')) 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path -LiteralPath $vswhere)) { Fail 'no vswhere.exe: the MSVC toolchain is not installed' }
    $found = & $vswhere -latest -products '*' -property installationPath | Select-Object -First 1
    if (-not $found) { Fail 'vswhere names no Visual Studio installation' }
    return "$found".Trim()
}

function Find-CMake {
    if ($CMake) { return $CMake }
    $onPath = Get-Command cmake.exe -ErrorAction SilentlyContinue
    if ($onPath) { return $onPath.Path }
    $installed = Join-Path $env:ProgramFiles 'CMake\bin\cmake.exe'
    if (Test-Path -LiteralPath $installed) { return $installed }
    Fail "no cmake.exe on PATH or at $installed; name one with -CMake"
}

# Batch lines run in the environment 'vcvarsall.bat <arch>' sets up, each line's output appended to $log;
# the exit status of the first line that failed, or 0. vcvarsall.bat's own exit status is not its verdict
# (an optional component it looks for and lacks sets it), so what is asked of it is that cl is then found.
# Its telemetry helper would inherit the redirected handle and keep the log open, so it is switched off,
# and the environment's own output goes to a file of its own.
function Invoke-InVs([string]$name, [string]$arch, [string[]]$lines, [string]$log) {
    $bat = Join-Path $script:WorkDir "$name.bat"
    $text = '@echo off' + $CRLF + 'set VSCMD_SKIP_SENDTELEMETRY=1' + $CRLF +
            'call ' + $Q + $script:VcVars + $Q + ' ' + $arch + ' > ' + $Q + $log + '.vcvars' + $Q + ' 2>&1' + $CRLF +
            'where cl >> ' + $Q + $log + $Q + ' 2>&1' + $CRLF + 'if errorlevel 1 exit /b 1' + $CRLF
    foreach ($line in $lines) {
        $text += $line + ' >> ' + $Q + $log + $Q + ' 2>&1' + $CRLF + 'if errorlevel 1 exit /b 1' + $CRLF
    }
    $text += 'exit /b 0' + $CRLF
    [System.IO.File]::WriteAllText($bat, $text, [System.Text.Encoding]::ASCII)
    $null = & cmd.exe /d /c $bat
    return $LASTEXITCODE
}

# The cache entries of pico's own options and of the build's type, generator and flags, as CMake holds them
# after the configure: what the build was, not what it was asked. None of them names a path of this machine.
function Get-CacheOptions([string]$cache) {
    $found = [ordered]@{}
    $wanted = '^(Z_[A-Z0-9_]+|ZP_[A-Z0-9_]+|ZENOH_[A-Z0-9_]+|BATCH_[A-Z0-9_]+|FRAG_[A-Z0-9_]+|BUILD_SHARED_LIBS|' +
              'BUILD_EXAMPLES|BUILD_TESTING|CMAKE_BUILD_TYPE|CMAKE_GENERATOR|CMAKE_GENERATOR_PLATFORM|CMAKE_C_FLAGS|' +
              'CMAKE_C_FLAGS_RELEASE|CMAKE_SHARED_LINKER_FLAGS|CMAKE_SHARED_LINKER_FLAGS_RELEASE):([A-Z]+)=(.*)$'
    foreach ($line in ($cache -split "\r?\n")) {
        if ($line -match $wanted -and $Matches[2] -ne 'INTERNAL') { $found[$Matches[1]] = $Matches[3] }
    }
    return $found
}

# -- the plan ------------------------------------------------------------------------------------------

foreach ($given in @(@('-Plan', $Plan), @('-PicoSource', $PicoSource))) {
    if (-not $given[1] -or -not (Test-Path -LiteralPath $given[1])) { Fail "$($given[0]) names nothing ('$($given[1])')" }
}
if (-not $Work) { Fail '-Work names no directory' }
if (-not $Out) { Fail '-Out names no directory' }
$planPath = (Resolve-Path -LiteralPath $Plan).Path
$planDoc = (Read-Text $planPath) | ConvertFrom-Json
if ($planDoc.schema -ne $PlanSchema) { Fail "$Plan is not a plan of schema $PlanSchema" }
$platform = "$($planDoc.cmake_platform)"
$compilerArch = "$($planDoc.vcvars)"
$config = "$($planDoc.reference_config)"
if (@('x64', 'Win32') -notcontains $platform) { Fail "the plan names no CMake platform of a width ('$platform')" }
if (@('x64', 'x86') -notcontains $compilerArch) { Fail "the plan names no compiler of a width ('$compilerArch')" }
if (-not $config) { Fail 'the plan names no build configuration' }
if ($null -eq $planDoc.reference_switches -or $null -eq $planDoc.reference_cmake) {
    Fail 'the plan names no switches or CMake arguments of the reference'
}

if (-not (Test-Path -LiteralPath $Work)) { [void](New-Item -ItemType Directory -Path $Work) }
$script:WorkDir = (Resolve-Path -LiteralPath $Work).Path
$script:VcVars = Join-Path (Find-VsRoot) 'VC\Auxiliary\Build\vcvarsall.bat'
if (-not (Test-Path -LiteralPath $script:VcVars)) { Fail "no vcvarsall.bat at $script:VcVars" }
$cmakeExe = Find-CMake

# -- the reference -------------------------------------------------------------------------------------

$source = Join-Path $script:WorkDir 'pico-src'
Reset-Directory $source
$givenSource = (Resolve-Path -LiteralPath $PicoSource).Path
if ($givenSource -like '*.zip') {
    Expand-Archive -LiteralPath $givenSource -DestinationPath $source
    $tops = @(Get-ChildItem -LiteralPath $source -Directory)
    if ($tops.Count -ne 1) { Fail "$PicoSource holds not one directory" }
    $picoTree = $tops[0].FullName
} else {
    $picoTree = Join-Path $source 'zenoh-pico'
    Copy-Item -Recurse -LiteralPath $givenSource -Destination $picoTree
}
if (-not (Test-Path -LiteralPath (Join-Path $picoTree 'CMakeLists.txt'))) { Fail "$PicoSource is no zenoh-pico tree (no CMakeLists.txt)" }

# A fresh tree: CMake keeps the flags of the first configure of a directory.
$build = Join-Path $script:WorkDir 'pico-build'
Reset-Directory $build
$switches = @($planDoc.reference_switches.PSObject.Properties | Sort-Object Name)
$arguments = @($planDoc.reference_cmake) + @($switches | ForEach-Object { '-D' + $_.Name + '=' + $_.Value })
$quoted = ($arguments | ForEach-Object { $Q + $_ + $Q }) -join ' '
$configure = $Q + $cmakeExe + $Q + ' -S ' + $Q + $picoTree + $Q + ' -B ' + $Q + $build + $Q + ' -G ' + $Q + $Generator + $Q +
             ' -A ' + $platform + ' ' + $quoted
$compile = $Q + $cmakeExe + $Q + ' --build ' + $Q + $build + $Q + ' --config ' + $config + ' --parallel'
$log = Join-Path $script:WorkDir 'build-reference.log'
if (Test-Path -LiteralPath $log) { Remove-Item -Force -LiteralPath $log }
if ((Invoke-InVs 'build-reference' $compilerArch @($configure, $compile) $log) -ne 0) { Fail "the zenoh-pico reference did not build (see $log)" }
$dll = @(Get-ChildItem -LiteralPath $build -Recurse -Filter 'zenohpico.dll' | Where-Object { $_.FullName -notmatch '\\CMakeFiles\\' })
if ($dll.Count -ne 1) { Fail "the reference build left $($dll.Count) zenohpico.dll under $build, not one" }
$header = Join-Path $build 'include\zenoh-pico\config.h'
if (-not (Test-Path -LiteralPath $header)) { Fail "the reference build left no $header" }

# The toolchain, in the words the reading gives it: cl's banner (it exits non-zero with no input) and CMake's.
$versionLog = Join-Path $script:WorkDir 'toolchain.log'
if (Test-Path -LiteralPath $versionLog) { Remove-Item -Force -LiteralPath $versionLog }
[void](Invoke-InVs 'toolchain' $compilerArch @(($Q + $cmakeExe + $Q + ' --version'), 'cl') $versionLog)
$said = @((Read-Text $versionLog) -split "\r?\n")
$compiler = @($said | Where-Object { $_ -match '^Microsoft \(R\) C/C\+\+' } | Select-Object -First 1)
$maker = @($said | Where-Object { $_ -match '^cmake version' } | Select-Object -First 1)
if ($compiler.Count -ne 1 -or $maker.Count -ne 1) { Fail "the toolchain did not state its versions (see $versionLog)" }

# -- the reading ---------------------------------------------------------------------------------------

$reading = [ordered]@{
    schema = $ReadingSchema
    date = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd')
    toolchain = ('{0}; {1}; generator {2} {3}' -f "$($compiler[0])".Trim(), "$($maker[0])".Trim(), $Generator, $platform)
    reference_cache = Get-CacheOptions (Read-Text (Join-Path $build 'CMakeCache.txt'))
}
if (-not (Test-Path -LiteralPath $Out)) { [void](New-Item -ItemType Directory -Path $Out) }
$outDir = (Resolve-Path -LiteralPath $Out).Path
Copy-Item -Force -LiteralPath $planPath -Destination (Join-Path $outDir 'plan.json')
Copy-Item -Force -LiteralPath $dll[0].FullName -Destination (Join-Path $outDir 'zenohpico.dll')
Copy-Item -Force -LiteralPath $header -Destination (Join-Path $outDir 'config.h')
Write-Text (Join-Path $outDir 'reading.json') ($reading | ConvertTo-Json -Depth 6)
Say ("zenoh-pico {0} for {1} built as the plan's same build ({2}); {3} switches set" -f
     "$($planDoc.reference_pin)", $platform, $reading.toolchain, $switches.Count)
Say "the reading is in $outDir; judge it with pico_windows_package.py --size-judge <the package zip> $outDir"
exit 0
