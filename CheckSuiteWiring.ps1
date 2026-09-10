# Copyright © 2026 Khrustal & Mann
#              MELBOURNE, VICTORIA, AUSTRALIA, 3000
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing
# permissions and limitations under the License.
#
<#
.SYNOPSIS
    Fail the build when a test suite is called but not actually compiled in.

.DESCRIPTION
    TestMain.cpp calls one Run<Name>Suite() per suite.  Each is defined in its
    own <Name>Suite.cpp, which must be listed in the .vcxproj.  Nothing enforced
    that, and on 2026-07-15 commit a5e9195 added UtilHubsSuite.cpp plus its call
    in TestMain.cpp but never touched MscsUnitTests(2026).vcxproj.  The call
    compiled, the definition did not, and the whole executable failed to link
    with LNK2019 -- so ALL 193 cases were dark on Windows for 14 days, not just
    the 9 new ones.  The CMake build was unaffected, which is why it went
    unnoticed.

    TestMain.cpp guards each call, e.g.

        #if !defined(MSCS_NO_TREEFS) && !defined(MSCS_NO_UTILHUBS)
            RunUtilHubsSuite();
        #endif

    so there are exactly two valid states per suite: compile the .cpp in, or
    define the opt-out macro.  CMake picks one or the other explicitly.  The
    .vcxproj was in neither -- the one combination guaranteed to fail.  This
    script enforces that invariant.

.NOTES
    Run by the PreBuildEvent; exits 1 to fail the build.  Run it by hand with
    -VerboseReport to see every suite and its state.

    The #if tracker understands #ifndef X, #if !defined(X) and nesting.  A call
    inside an #else / #elif branch is reported as unverifiable rather than
    guessed at -- none currently are.
#>
[CmdletBinding()]
param(
    [string] $ProjectDir,
    [string] $ProjectFile,
    # The runner whose Run<Name>Suite() calls are checked against $ProjectFile.
    # Added with the 2026-08-14 split: there are two runners now -- this
    # directory's TestMain.cpp and MscsUnitTestsExternal's TestMainExternal.cpp
    # -- and the invariant is per-runner. Parameterised rather than duplicated,
    # because a second copy of this checker would drift exactly like every other
    # duplicated thing in this tree has.
    [string] $TestMainFile,
    [switch] $VerboseReport
)

$ErrorActionPreference = 'Stop'

# $PSScriptRoot is not populated in a param() default under -File, so resolve here.
if (-not $ProjectDir) { $ProjectDir = $PSScriptRoot }
if (-not $ProjectDir) { $ProjectDir = Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $ProjectDir) { $ProjectDir = (Get-Location).Path }

if (-not $ProjectFile) {
    $ProjectFile = Get-ChildItem -LiteralPath $ProjectDir -Filter '*.vcxproj' |
                   Where-Object { $_.Name -like 'MscsUnitTests*' } |
                   Select-Object -First 1 -ExpandProperty FullName
}
if ($TestMainFile) {
    $testMain = if ([System.IO.Path]::IsPathRooted($TestMainFile)) { $TestMainFile }
                else { Join-Path $ProjectDir $TestMainFile }
} else {
    $testMain = Join-Path $ProjectDir 'TestMain.cpp'
}

foreach ($f in @($ProjectFile, $testMain)) {
    if (-not $f -or -not (Test-Path -LiteralPath $f)) {
        Write-Host "CheckSuiteWiring: cannot find required file '$f'" -ForegroundColor Red
        exit 1
    }
}

# ---------------------------------------------------------------------------
# 1. Every Run<Name>Suite() call in TestMain.cpp, with the macros guarding it.
# ---------------------------------------------------------------------------
$calls  = @{}                       # suite name -> string[] of guard macros
$guards = New-Object System.Collections.Stack

foreach ($line in [System.IO.File]::ReadAllLines($testMain)) {
    if ($line -match '^\s*#\s*ifndef\s+(\w+)') {
        # #ifndef X is the same opt-out shape as #if !defined(X).
        $guards.Push(@($Matches[1]))
    }
    elseif ($line -match '^\s*#\s*if') {
        $macros = @([regex]::Matches($line, '!\s*defined\s*\(\s*(\w+)\s*\)') |
                    ForEach-Object { $_.Groups[1].Value })
        $guards.Push($macros)
    }
    elseif ($line -match '^\s*#\s*(else|elif)') {
        # The opposite branch: a call here is reachable when the macro IS defined,
        # which inverts the logic. Mark it rather than guess -- calls inside are
        # reported as unverifiable instead of silently mis-classified.
        if ($guards.Count -gt 0) { [void]$guards.Pop() }
        $guards.Push(@('<inverted>'))
    }
    elseif ($line -match '^\s*#\s*endif') {
        if ($guards.Count -gt 0) { [void]$guards.Pop() }
    }
    elseif ($line -match '(?<!\w)Run(\w+)Suite\s*\(') {
        $name = $Matches[1]
        if (-not $calls.ContainsKey($name)) {
            $calls[$name] = @($guards.ToArray() | ForEach-Object { $_ })
        }
    }
}

# ---------------------------------------------------------------------------
# 2. Which .cpp defines each suite, and what the project compiles / defines.
# ---------------------------------------------------------------------------
$definedBy = @{}                    # suite name -> file name
foreach ($f in Get-ChildItem -LiteralPath $ProjectDir -Filter '*.cpp') {
    foreach ($m in [regex]::Matches([System.IO.File]::ReadAllText($f.FullName),
                                    '(?m)^\s*void\s+Run(\w+)Suite\s*\(')) {
        $definedBy[$m.Groups[1].Value] = $f.Name
    }
}

[xml]$xml = Get-Content -LiteralPath $ProjectFile -Raw
$ns = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
$ns.AddNamespace('m', 'http://schemas.microsoft.com/developer/msbuild/2003')

$compiled = @($xml.SelectNodes('//m:ClCompile[@Include]', $ns) |
              ForEach-Object { Split-Path $_.Include -Leaf })
$defines  = @($xml.SelectNodes('//m:PreprocessorDefinitions', $ns) |
              ForEach-Object { $_.InnerText -split ';' } |
              ForEach-Object { $_.Trim() } | Where-Object { $_ })

# ---------------------------------------------------------------------------
# 3. Check the invariant.
# ---------------------------------------------------------------------------
$errors = @()
$warns  = @()

foreach ($name in ($calls.Keys | Sort-Object)) {
    $optedOut = @($calls[$name] | Where-Object { $defines -contains $_ })
    $file     = $definedBy[$name]

    if ($calls[$name] -contains '<inverted>') {
        $warns += ("Run${name}Suite() is called inside an #else/#elif branch; this script " +
                   "cannot determine whether it is active. Verify by hand.")
        continue
    }
    if ($optedOut.Count -gt 0) {
        if ($VerboseReport) { Write-Host ("  {0,-20} opted out via {1}" -f $name, ($optedOut -join ',')) }
        continue
    }
    if (-not $file) {
        $errors += "Run${name}Suite() is called in TestMain.cpp but no .cpp in this folder defines it."
        continue
    }
    if ($compiled -notcontains $file) {
        $errors += ("Run${name}Suite() is called in TestMain.cpp and defined in ${file}, " +
                    "but ${file} is NOT in $(Split-Path $ProjectFile -Leaf). " +
                    "Add <ClCompile Include=`"${file}`" /> or define one of: " +
                    $(if ($calls[$name]) { $calls[$name] -join ', ' } else { '(no opt-out macro on this call)' }) + '.')
        continue
    }
    if ($VerboseReport) { Write-Host ("  {0,-20} OK  ({1})" -f $name, $file) }
}

# Compiled but never called -- not fatal, but it is dead weight or a missed call.
foreach ($name in ($definedBy.Keys | Sort-Object)) {
    if (-not $calls.ContainsKey($name) -and $compiled -contains $definedBy[$name]) {
        $warns += "$($definedBy[$name]) defines Run${name}Suite() but TestMain.cpp never calls it."
    }
}

foreach ($w in $warns)  { Write-Host "CheckSuiteWiring: warning: $w" -ForegroundColor Yellow }

if ($errors.Count -gt 0) {
    Write-Host ''
    foreach ($e in $errors) { Write-Host "CheckSuiteWiring: error: $e" -ForegroundColor Red }
    Write-Host ''
    Write-Host "Build stopped: a suite is called but not compiled in; the link would" -ForegroundColor Red
    Write-Host "fail with LNK2019 and NO tests would run.  See the header of" -ForegroundColor Red
    Write-Host "CheckSuiteWiring.ps1." -ForegroundColor Red
    exit 1
}

Write-Host "CheckSuiteWiring: $($calls.Count) suite(s) wired correctly."
exit 0
