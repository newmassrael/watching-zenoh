# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
<#
The pico ABI performance matrix on Windows x64 (docs/pico-perf-matrix.md section 6): the runner of
scripts/host-bench/perf_matrix.py for a host it cannot run on (no taskset, no /proc, no SIGTERM, no
Python of the tree's floor). The gate stays on Linux: this writes a reading of the shape
'perf_matrix.py run' writes, its record's platform windows-x64, which 'perf_matrix.py --gate' judges
against deploy/pico_perf_ceiling_windows.json.

  perf_matrix.ps1 -Mode all -Plan plan.json -PicoSource DIR|ZIP -Package ZIP -Probe perf_probe.c -Work DIR
                  [-ClientCpus 4-7] [-ServerCpus 8-11] [-Reps 3] [-Sizes 8,64,1024] [-Transports tcp,udp,multicast]
                  [-Batching off,on] [-Workloads rtt,thr] [-Pings 20000] [-GroupInterface {GUID}]
  perf_matrix.ps1 -Mode idle-cpus [-IdleSeconds 10] [-PerSide 4]

Modes: build (arm P and the probe against each arm, into -Work), run (the matrix over what build left
in -Work), all (both), idle-cpus (each CPU's busy share and a pinning of two sides of whole cores, the
least busy first, printed as the words -ClientCpus and -ServerCpus take).

The plan ('perf_matrix.py windows-plan PACKAGE OUT', made on Linux from the package) names arm W's
package by its digest, arm P's switches, the figures and the rules of a cell (the foreign-use limit,
the runs a disturbed cell is given, the settle, the tail, the readiness bound), so nothing here
restates them.

Arm P is zenoh-pico from -PicoSource (an export of the pinned vendor/zenoh-pico), configured by
CMake's Visual Studio generator for x64, Release, shared, without examples and tests, with the plan's
switches: the configuration capability_cost_gate.pico_reference_tree gives it on Linux. The cache
entries of pico's own options and every switch pico built otherwise than asked are recorded. Arm W is
the package's release DLL. perf_probe.c is compiled against each with MSVC.

A cell runs as on Linux: the server side, then the client side, each started suspended, pinned with
SetProcessAffinityMask to -ServerCpus or -ClientCpus and resumed, so none of it runs elsewhere (taskset
on Linux); its stdout and stderr in one file; stopped by its named event where Linux sends SIGTERM, and
terminated if it has not ended 5 s later. The whole CPU of a process is GetProcessTimes of it once it
ended, and its peak working set is its own last line. A cell counts when the pinned CPUs were used by
nothing else: their busy time (kernel less idle, interrupts and DPCs, plus user; nodrop.py leaves
interrupts out on Linux alike) less the CPU of the two processes, over the CPU seconds the cell had, at
most the plan's limit; a disturbed cell is run again, and once more after the last repetition.

Multicast joins the plan's group on the adapter of the default route (-GroupInterface names another by
its GUID), since the loopback adapter of Windows carries no group. Before the matrix each arm is asked
for a short round trip on it; when neither arm forms a group, the host does not carry one to its own
members (the adapter, or a firewall that drops the datagrams), the transport is left out, and the
record says why. No firewall rule is read or changed.

Exit status: 0 when the mode ran, 2 when an input is refused or a build failed (the log is named),
64 for a usage error.
#>
[CmdletBinding()]
param(
    [ValidateSet('all', 'build', 'run', 'idle-cpus')][string]$Mode = 'all',
    [string]$Plan = '',
    [string]$PicoSource = '',
    [string]$Package = '',
    [string]$Probe = '',
    [string]$Work = '',
    [int]$Reps = 3,
    [string]$Sizes = '8,64,1024',
    [string]$Transports = 'tcp,udp,multicast',
    [string]$Batching = 'off,on',
    [string]$Workloads = 'rtt,thr',
    [string]$ClientCpus = '4-7',
    [string]$ServerCpus = '8-11',
    [int]$Pings = 20000,
    [int]$WarmupMs = 3000,
    [int]$WindowS = 5,
    [int]$TimeoutMs = 100,
    [string]$GroupInterface = '',
    [string]$CMake = '',
    [string]$Generator = 'Visual Studio 17 2022',
    [double]$IdleSeconds = 10,
    [int]$PerSide = 4
)

$ErrorActionPreference = 'Stop'
# Windows PowerShell 5.1 writes an array that passed through a pipeline as {"value": [...], "Count": n} while
# the extended type data of System.Array is loaded; the reading is read by Python and must hold plain arrays.
Remove-TypeData System.Array -ErrorAction SilentlyContinue
[System.Threading.Thread]::CurrentThread.CurrentCulture = [System.Globalization.CultureInfo]::InvariantCulture
$Utf8 = New-Object System.Text.UTF8Encoding $false

# -- the host's own readings: processes, CPU times, topology ------------------------------------------------

if (-not ('WzPerfNative' -as [type])) {
    Add-Type -Language CSharp -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

public class WzPerfChild {
    public IntPtr Process;
    public int Pid;
}

public static class WzPerfNative {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO {
        public int cb; public string lpReserved; public string lpDesktop; public string lpTitle;
        public int dwX; public int dwY; public int dwXSize; public int dwYSize;
        public int dwXCountChars; public int dwYCountChars; public int dwFillAttribute; public int dwFlags;
        public short wShowWindow; public short cbReserved2; public IntPtr lpReserved2;
        public IntPtr hStdInput; public IntPtr hStdOutput; public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION {
        public IntPtr hProcess; public IntPtr hThread; public int dwProcessId; public int dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SECURITY_ATTRIBUTES {
        public int nLength; public IntPtr lpSecurityDescriptor; public int bInheritHandle;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateProcessW(string application, StringBuilder commandLine, IntPtr processAttributes,
        IntPtr threadAttributes, bool inheritHandles, uint flags, IntPtr environment, string directory,
        ref STARTUPINFO startup, out PROCESS_INFORMATION information);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateFileW(string name, uint access, uint share, ref SECURITY_ATTRIBUTES attributes,
        uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetProcessAffinityMask(IntPtr process, UIntPtr mask);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateProcess(IntPtr process, uint code);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetExitCodeProcess(IntPtr process, out uint code);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetProcessTimes(IntPtr process, out long created, out long exited, out long kernel,
        out long user);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenEventW(uint access, bool inherit, string name);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetEvent(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetLogicalProcessorInformation(IntPtr buffer, ref uint length);
    [DllImport("ntdll.dll")]
    private static extern int NtQuerySystemInformation(int infoClass, IntPtr buffer, int length, out int returned);

    private static readonly IntPtr Invalid = new IntPtr(-1);
    private const uint GenericRead = 0x80000000, GenericWrite = 0x40000000, ShareReadWrite = 3;
    private const uint CreateAlways = 2, OpenExisting = 3, Normal = 0x80;
    private const uint CreateSuspended = 0x4, CreateNoWindow = 0x08000000, UseStdHandles = 0x100;
    private const uint EventModifyState = 0x2;
    private const int ProcessorPerformance = 8, PerformanceRecord = 48, MaxCpus = 64;

    private static string Quote(string word) {
        if (word.Length > 0 && word.IndexOfAny(new char[] { ' ', '\t', '"' }) < 0) return word;
        return "\"" + word.Replace("\"", "\\\"") + "\"";
    }

    // The program started suspended, its affinity set to mask, then resumed: no instruction of it runs on
    // another CPU, as with taskset. Its stdout and stderr are one file.
    public static WzPerfChild Start(string program, string[] words, string directory, string output, ulong mask) {
        StringBuilder line = new StringBuilder(Quote(program));
        foreach (string word in words) { line.Append(' '); line.Append(Quote(word)); }
        SECURITY_ATTRIBUTES inherit = new SECURITY_ATTRIBUTES();
        inherit.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
        inherit.bInheritHandle = 1;
        IntPtr file = CreateFileW(output, GenericWrite, ShareReadWrite, ref inherit, CreateAlways, Normal, IntPtr.Zero);
        if (file == Invalid) throw new Win32Exception(Marshal.GetLastWin32Error(), "cannot write " + output);
        IntPtr nothing = CreateFileW("NUL", GenericRead, ShareReadWrite, ref inherit, OpenExisting, Normal, IntPtr.Zero);
        if (nothing == Invalid) {
            int failed = Marshal.GetLastWin32Error();
            CloseHandle(file);
            throw new Win32Exception(failed, "cannot open NUL");
        }
        STARTUPINFO startup = new STARTUPINFO();
        startup.cb = Marshal.SizeOf(typeof(STARTUPINFO));
        startup.dwFlags = (int)UseStdHandles;
        startup.hStdInput = nothing;
        startup.hStdOutput = file;
        startup.hStdError = file;
        PROCESS_INFORMATION information;
        bool started = CreateProcessW(program, line, IntPtr.Zero, IntPtr.Zero, true, CreateSuspended | CreateNoWindow,
            IntPtr.Zero, directory, ref startup, out information);
        int error = Marshal.GetLastWin32Error();
        CloseHandle(file);
        CloseHandle(nothing);
        if (!started) throw new Win32Exception(error, "cannot start " + program);
        if (!SetProcessAffinityMask(information.hProcess, new UIntPtr(mask))) {
            error = Marshal.GetLastWin32Error();
            TerminateProcess(information.hProcess, 1);
            CloseHandle(information.hThread);
            CloseHandle(information.hProcess);
            throw new Win32Exception(error, "cannot pin " + program);
        }
        ResumeThread(information.hThread);
        CloseHandle(information.hThread);
        WzPerfChild child = new WzPerfChild();
        child.Process = information.hProcess;
        child.Pid = information.dwProcessId;
        return child;
    }

    public static bool Wait(WzPerfChild child, double seconds) {
        double ms = Math.Max(0.0, Math.Min(seconds * 1000.0, 4000000000.0));
        return WaitForSingleObject(child.Process, (uint)ms) == 0;
    }

    public static bool Ended(WzPerfChild child) {
        return WaitForSingleObject(child.Process, 0) == 0;
    }

    // Set the named event the probe waits on (it makes it a moment after it starts, so it is looked for
    // again until the time is up), then wait; terminated when it has not ended by then. Whether it ended
    // on its own.
    public static bool Stop(WzPerfChild child, string name, int milliseconds) {
        DateTime until = DateTime.UtcNow.AddMilliseconds(milliseconds);
        while (!Ended(child)) {
            IntPtr handle = OpenEventW(EventModifyState, false, name);
            if (handle != IntPtr.Zero) {
                SetEvent(handle);
                CloseHandle(handle);
                break;
            }
            if (DateTime.UtcNow >= until) break;
            System.Threading.Thread.Sleep(20);
        }
        double left = (until - DateTime.UtcNow).TotalMilliseconds;
        if (WaitForSingleObject(child.Process, (uint)Math.Max(0.0, left)) == 0) return true;
        TerminateProcess(child.Process, 137);
        WaitForSingleObject(child.Process, 5000);
        return false;
    }

    public static int ExitCode(WzPerfChild child) {
        uint code;
        return GetExitCodeProcess(child.Process, out code) ? (int)code : -1;
    }

    // The user and the kernel seconds of every thread of the process.
    public static double[] Times(WzPerfChild child) {
        long created, exited, kernel, user;
        if (!GetProcessTimes(child.Process, out created, out exited, out kernel, out user)) return new double[] { 0.0, 0.0 };
        return new double[] { user / 1e7, kernel / 1e7 };
    }

    public static void Close(WzPerfChild child) {
        if (child.Process != IntPtr.Zero) {
            CloseHandle(child.Process);
            child.Process = IntPtr.Zero;
        }
    }

    // Each CPU's busy seconds and its whole seconds so far: busy is kernel less idle, less the time of
    // interrupts and deferred procedure calls, plus user; whole is kernel (which holds idle) plus user.
    public static double[][] Sample() {
        IntPtr buffer = Marshal.AllocHGlobal(PerformanceRecord * MaxCpus);
        try {
            int returned;
            int status = NtQuerySystemInformation(ProcessorPerformance, buffer, PerformanceRecord * MaxCpus, out returned);
            if (status != 0) throw new Win32Exception("NtQuerySystemInformation answered 0x" + status.ToString("X8"));
            int count = returned / PerformanceRecord;
            double[] busy = new double[count];
            double[] whole = new double[count];
            for (int cpu = 0; cpu < count; cpu++) {
                int at = cpu * PerformanceRecord;
                long idle = Marshal.ReadInt64(buffer, at);
                long kernel = Marshal.ReadInt64(buffer, at + 8);
                long user = Marshal.ReadInt64(buffer, at + 16);
                long dpc = Marshal.ReadInt64(buffer, at + 24);
                long interrupt = Marshal.ReadInt64(buffer, at + 32);
                busy[cpu] = (kernel - idle - dpc - interrupt + user) / 1e7;
                whole[cpu] = (kernel + user) / 1e7;
            }
            return new double[][] { busy, whole };
        } finally {
            Marshal.FreeHGlobal(buffer);
        }
    }

    // Each logical CPU's physical core, by the order of the core's record; -1 for a CPU no record names.
    public static int[] CoreOf() {
        uint length = 0;
        GetLogicalProcessorInformation(IntPtr.Zero, ref length);
        IntPtr buffer = Marshal.AllocHGlobal((int)length);
        try {
            if (!GetLogicalProcessorInformation(buffer, ref length)) throw new Win32Exception(Marshal.GetLastWin32Error());
            int size = IntPtr.Size == 8 ? 32 : 24;
            int[] core = new int[MaxCpus];
            for (int cpu = 0; cpu < MaxCpus; cpu++) core[cpu] = -1;
            int index = 0;
            for (int at = 0; at + size <= (int)length; at += size) {
                ulong mask = unchecked((ulong)Marshal.ReadIntPtr(buffer, at).ToInt64());
                int relation = Marshal.ReadInt32(buffer, at + IntPtr.Size);
                if (relation != 0) continue;
                for (int cpu = 0; cpu < MaxCpus; cpu++) {
                    if (((mask >> cpu) & 1UL) != 0) core[cpu] = index;
                }
                index++;
            }
            return core;
        } finally {
            Marshal.FreeHGlobal(buffer);
        }
    }
}
'@
}

# -- small pieces ------------------------------------------------------------------------------------------

function Fail([string]$why) {
    [Console]::Out.WriteLine("perf-matrix-windows: NOT-MEASURED, $why")
    exit 2
}

function Say([string]$line) { [Console]::Out.WriteLine("perf-matrix-windows: $line") }

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

function Get-Prop($object, [string]$name) {
    if ($null -eq $object) { return $null }
    $property = $object.PSObject.Properties[$name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Get-UtcText([string]$format) { return (Get-Date).ToUniversalTime().ToString($format) }

# '6,7' or '6-9,12' as the CPUs they name (nodrop.cpu_list).
function Get-CpuList([string]$spec) {
    $out = New-Object System.Collections.Generic.List[int]
    foreach ($part in $spec.Split(',')) {
        if ($part -match '^(\d+)-(\d+)$') {
            for ($cpu = [int]$Matches[1]; $cpu -le [int]$Matches[2]; $cpu++) { $out.Add($cpu) }
        } elseif ($part -match '^\d+$') {
            $out.Add([int]$part)
        } elseif ($part -ne '') {
            Fail "the CPU list '$spec' is not of the form 6,7 or 6-9,12"
        }
    }
    return ,$out.ToArray()
}

function Get-Mask([int[]]$cpus) {
    [uint64]$mask = 0
    foreach ($cpu in $cpus) { $mask = $mask -bor ([uint64]1 -shl $cpu) }
    return $mask
}

function Get-Words([string]$list) { return ,@($list.Split(',') | Where-Object { $_ -ne '' }) }

# -- the readers, as perf_matrix.py reads a program's lines --------------------------------------------------

# The key=value words of the last line 'perf_probe <role> ...' that carries every one of $keys, or $null.
function Get-Fields([string]$text, [string]$role, $keys) {
    $found = $null
    $prefix = "perf_probe $role "
    foreach ($line in ($text -split "\r?\n")) {
        if (-not $line.StartsWith($prefix)) { continue }
        $words = @{}
        foreach ($word in $line.Substring($prefix.Length).Split(' ')) {
            $at = $word.IndexOf('=')
            if ($at -gt 0) { $words[$word.Substring(0, $at)] = $word.Substring($at + 1) }
        }
        $all = $true
        foreach ($key in $keys) { if (-not $words.ContainsKey($key)) { $all = $false } }
        if ($all) { $found = $words }
    }
    return $found
}

function Get-LastWords([string]$text) {
    $lines = @($text -split "\r?\n" | Where-Object { $_.Trim() -ne '' })
    if ($lines.Count -eq 0) { return 'nothing' }
    $last = $lines[$lines.Count - 1]
    if ($last.Length -gt 160) { $last = $last.Substring(0, 160) }
    return $last
}

# -- the probes and the cells ------------------------------------------------------------------------------

$script:Live = New-Object System.Collections.ArrayList

function Start-ProbeProcess([string]$binary, [string]$role, [string[]]$words, [string]$side, [string]$tag) {
    $mask = if ($side -eq 'client') { $script:ClientMask } else { $script:ServerMask }
    $out = Join-Path $script:RunDir "$tag.$role.out"
    $program = Join-Path $script:BinDir $binary
    $child = [WzPerfNative]::Start($program, [string[]](@($role) + $words), $script:BinDir, $out, $mask)
    $probe = @{ Child = $child; Out = $out; Role = $role; Ended = $false }
    [void]$script:Live.Add($probe)
    return $probe
}

function Wait-Probe($probe, [double]$seconds) { return [WzPerfNative]::Wait($probe.Child, $seconds) }

function Stop-Probe($probe) {
    if ($probe.Ended) { return }
    [void][WzPerfNative]::Stop($probe.Child, "Local\perf_probe_stop_$($probe.Child.Pid)", 5000)
    $probe.Ended = $true
}

# The whole CPU of the ended process and its peak working set (its own last line; 0 when it was ended before
# it printed one, as a child Linux could not reap has no rusage).
function Get-Usage($probe) {
    $times = [WzPerfNative]::Times($probe.Child)
    $rss = 0
    $line = Get-Fields (Read-Text $probe.Out) 'usage' @('peak_rss_kib')
    if ($null -ne $line) { $rss = [long]$line['peak_rss_kib'] }
    return @{ User = [double]$times[0]; Sys = [double]$times[1]; Rss = $rss }
}

function Close-Probe($probe) {
    [WzPerfNative]::Close($probe.Child)
    $script:Live.Remove($probe)
}

function Stop-Live {
    foreach ($probe in @($script:Live)) {
        Stop-Probe $probe
        Close-Probe $probe
    }
}

function Get-ProcessFigures($client, $server) {
    $figures = [ordered]@{}
    $figures['cpu_user_s_client'] = $client.User
    $figures['cpu_sys_s_client'] = $client.Sys
    $figures['cpu_user_s_server'] = $server.User
    $figures['cpu_sys_s_server'] = $server.Sys
    $figures['rss_kib_client'] = $client.Rss
    $figures['rss_kib_server'] = $server.Rss
    $figures['rss_kib'] = $client.Rss + $server.Rss
    return $figures
}

# rtt_figures of perf_matrix.py: a string (why the cell is lost) or the figures.
function Get-RttFigures($ping, $pong, $client, $server) {
    $counted = [long]$ping['round_trips']
    if ($counted -eq 0) { return "no round trip came back ($($ping['lost']) lost)" }
    $figures = [ordered]@{}
    $figures['rtt_p50_us'] = [double]$ping['p50_ns'] / 1e3
    $figures['rtt_p90_us'] = [double]$ping['p90_ns'] / 1e3
    $figures['rtt_p99_us'] = [double]$ping['p99_ns'] / 1e3
    $figures['rtt_mean_us'] = [double]$ping['mean_ns'] / 1e3
    $figures['rtt_min_us'] = [double]$ping['min_ns'] / 1e3
    $figures['rtt_max_us'] = [double]$ping['max_ns'] / 1e3
    $figures['round_trips'] = $counted
    $figures['lost'] = [long]$ping['lost']
    $figures['ping_cpu_ns_per_rtt'] = [double]$ping['cpu_ns'] / [math]::Max(1, [long]$ping['all_round_trips'])
    $figures['pong_cpu_ns_per_rtt'] = $null
    if ($null -ne $pong -and $pong['stopped_by'] -eq 'stop' -and [long]$pong['answered'] -gt 0) {
        $figures['pong_cpu_ns_per_rtt'] = [double]$pong['cpu_ns'] / [long]$pong['answered']
    }
    foreach ($entry in (Get-ProcessFigures $client $server).GetEnumerator()) { $figures[$entry.Key] = $entry.Value }
    return $figures
}

# thr_figures of perf_matrix.py: a string (why the cell is lost) or the figures.
function Get-ThrFigures($pub, $sub, $client, $server) {
    $pubStart = [long]$pub['start_ns']; $pubEnd = [long]$pub['end_ns']
    $subStart = [long]$sub['start_ns']; $subEnd = [long]$sub['end_ns']
    if (-not ($pubStart -le $subStart -and $subStart -le $subEnd -and $subEnd -le $pubEnd)) {
        return ("the subscriber's window was not inside the publisher's loop (window {0}..{1}, loop {2}..{3})" -f
                $sub['start_ns'], $sub['end_ns'], $pub['start_ns'], $pub['end_ns'])
    }
    $received = [long]$sub['received']; $sent = [long]$pub['sent']
    if ($received -eq 0 -or $sent -eq 0) { return "$sent put, $received delivered in the window" }
    $window = [double]$sub['window_ns'] / 1e9
    $pubCpu = [double]$pub['cpu_ns'] / $sent
    $subCpu = [double]$sub['cpu_ns'] / $received
    $figures = [ordered]@{}
    $figures['msgs_per_s'] = $received / $window
    $figures['bytes_per_s'] = [double]$sub['bytes'] / $window
    $figures['offered_msgs_per_s'] = $sent / ([double]$pub['elapsed_ns'] / 1e9)
    $figures['put_failed'] = [long]$pub['failed']
    $figures['cpu_ns_per_msg_pub'] = $pubCpu
    $figures['cpu_ns_per_msg_sub'] = $subCpu
    $figures['cpu_ns_per_msg'] = $pubCpu + $subCpu
    foreach ($entry in (Get-ProcessFigures $client $server).GetEnumerator()) { $figures[$entry.Key] = $entry.Value }
    return $figures
}

function Get-Or($words, [string]$key, [string]$default) {
    if ($words.ContainsKey($key)) { return $words[$key] }
    return $default
}

# stall_note of perf_matrix.py: which side stopped, in a throughput cell that delivered nothing.
function Get-StallNote($pub, $subEnd) {
    $start = [long]$pub['start_ns']
    $facts = New-Object System.Collections.Generic.List[string]
    $facts.Add("$(Get-Or $pub 'batch_cycles' '?') batch window(s)")
    $facts.Add("$($pub['failed']) put(s) failed")
    $lostMatch = [long](Get-Or $pub 'lost_match_ns' '0')
    if ($lostMatch -ne 0) {
        $facts.Add(("the publisher matched no subscriber from {0:F2} s into its loop" -f (($lostMatch - $start) / 1e9)))
    }
    $facts.Add("the publisher listed $(Get-Or $pub 'peers_at_end' '?') peer(s) at its end")
    if ($null -ne $subEnd) {
        $grew = [long]$subEnd['last_growth_ns']
        $when = if ($grew -ne 0) { "{0:F2} s into the publisher's loop" -f (($grew - $start) / 1e9) } else { 'never' }
        $facts.Add("the subscriber received $($subEnd['total']) in all, its count last grew $when, and it listed $($subEnd['peers']) peer(s) at its end")
    }
    if ($lostMatch -ne 0 -or (Get-Or $pub 'peers_at_end' '') -eq '0') {
        $side = 'the sending side lost the subscriber, and its puts went nowhere'
    } elseif ((Get-Or $pub 'matched_at_end' '') -eq '1' -and $null -ne $subEnd) {
        $side = 'the publisher still matched its subscriber at its end, so what stopped is on the receiving side or the link between'
    } else {
        $side = 'which side stopped is not told by these lines'
    }
    return "$side ($($facts -join '; '))"
}

function Test-PortFree([string]$transport, [int]$port) {
    try {
        if ($transport -eq 'tcp') {
            $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $port)
            $listener.Start()
            $listener.Stop()
        } elseif ($transport -eq 'udp') {
            $at = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Loopback, $port)
            $socket = New-Object System.Net.Sockets.UdpClient($at)
            $socket.Close()
        } else {
            $socket = New-Object System.Net.Sockets.UdpClient($port)
            $socket.Close()
        }
        return $true
    } catch {
        return $false
    }
}

# endpoint_args of perf_matrix.py, at a port this host lets the transport bind: a Windows host reserves port
# ranges of its own (Hyper-V, WSL), and a port drawn inside one would lose the cell to the host.
function Get-Endpoints([string]$transport) {
    $port = 0
    for ($try = 0; $try -lt 50 -and $port -eq 0; $try++) {
        $candidate = 20000 + (Get-Random -Maximum 20000)
        if (Test-PortFree $transport $candidate) { $port = $candidate }
    }
    if ($port -eq 0) { Fail "no port from 20000 to 39999 could be bound for $transport in 50 draws" }
    if ($transport -eq 'tcp' -or $transport -eq 'udp') {
        $where = "$transport/127.0.0.1:$port"
        return @{ Server = @('-l', $where); Client = @('-e', $where, '-M') }
    }
    if ($transport -eq 'multicast') {
        $where = "udp/$($script:PlanDoc.group):$port#iface=$($script:GroupGuid)"
        return @{ Server = @('-l', $where); Client = @('-l', $where) }
    }
    Fail "no transport $transport on Windows"
}

function Get-CpuBusy {
    $sample = [WzPerfNative]::Sample()
    $total = 0.0
    foreach ($cpu in $script:PinnedCpus) { $total += $sample[0][$cpu] }
    return $total
}

$LF = [string][char]10
$CRLF = [string][char]13 + [string][char]10
$Q = '"'

# One run of a cell: @{ Lost = why } or @{ Figures }, and the CPU seconds its two processes had (Own).
function Invoke-CellOnce([string]$binary, [string]$transport, [bool]$batching, [string]$workload, [int]$size,
                         [string]$tag) {
    $flags = @()
    if ($batching) { $flags = @('-b') }
    $endpoints = Get-Endpoints $transport
    $settleMs = [int]([double]$script:PlanDoc.settle_s * 1000)
    $client = $null
    $server = $null
    if ($workload -eq 'rtt') {
        $deadline = $WarmupMs / 1e3 + [double]$script:PlanDoc.ready_s + $Pings * 1e-3 +
                    ([math]::Floor($Pings / 10) + 1) * $TimeoutMs / 1e3 + 30
        $server = Start-ProbeProcess $binary 'pong' (@('-m', 'peer') + $endpoints.Server + $flags) 'server' $tag
        try {
            Start-Sleep -Milliseconds $settleMs
            $client = Start-ProbeProcess $binary 'ping' (@('-m', 'peer') + $endpoints.Client +
                @('-s', "$size", '-n', "$Pings", '-w', "$WarmupMs", '-o', "$TimeoutMs") + $flags) 'client' $tag
            $done = Wait-Probe $client $deadline
            Stop-Probe $client
            [void](Wait-Probe $server 5.0)
        } finally {
            if ($null -ne $client) { Stop-Probe $client }
            Stop-Probe $server
        }
        $clientText = Read-Text $client.Out
        $serverText = Read-Text $server.Out
        if (-not $done) {
            $result = @{ Lost = ("ping did not finish in {0:F0} s" -f $deadline) }
        } else {
            $ping = Get-Fields $clientText 'ping' $script:PlanDoc.line_keys.ping
            if ($null -eq $ping) {
                $result = @{ Lost = "ping gave no result; it said: $(Get-LastWords $clientText); pong said: $(Get-LastWords $serverText)" }
            } else {
                $pong = Get-Fields $serverText 'pong' $script:PlanDoc.line_keys.pong
                $figures = Get-RttFigures $ping $pong (Get-Usage $client) (Get-Usage $server)
                if ($figures -is [string]) { $result = @{ Lost = $figures } } else { $result = @{ Figures = $figures } }
            }
        }
    } else {
        $pubSeconds = [int]([math]::Ceiling($WarmupMs / 1e3 + $WindowS)) + [int]$script:PlanDoc.pub_tail_s
        $server = Start-ProbeProcess $binary 'sub' (@('-m', 'peer') + $endpoints.Server +
            @('-w', "$WarmupMs", '-t', "$WindowS")) 'server' $tag
        try {
            Start-Sleep -Milliseconds $settleMs
            $client = Start-ProbeProcess $binary 'pub' (@('-m', 'peer') + $endpoints.Client +
                @('-s', "$size", '-t', "$pubSeconds") + $flags) 'client' $tag
            $done = Wait-Probe $client ($pubSeconds + [double]$script:PlanDoc.ready_s + 30)
        } finally {
            if ($null -ne $client) { Stop-Probe $client }
            Stop-Probe $server
        }
        $clientText = Read-Text $client.Out
        $serverText = Read-Text $server.Out
        if (-not $done) {
            $result = @{ Lost = 'pub did not finish in time' }
        } else {
            $put = Get-Fields $clientText 'pub' $script:PlanDoc.line_keys.pub
            $got = Get-Fields $serverText 'sub' $script:PlanDoc.line_keys.sub
            if ($null -eq $put) {
                $result = @{ Lost = "pub gave no result; it said: $(Get-LastWords $clientText)" }
            } elseif ($null -eq $got) {
                $result = @{ Lost = "sub gave no window; it said: $(Get-LastWords $serverText)" }
            } else {
                $figures = Get-ThrFigures $put $got (Get-Usage $client) (Get-Usage $server)
                if ($figures -is [string]) {
                    $note = Get-StallNote $put (Get-Fields $serverText 'sub' $script:PlanDoc.line_keys.sub_end)
                    $result = @{ Lost = "$figures; $note" }
                } else {
                    $result = @{ Figures = $figures }
                }
            }
        }
    }
    $own = 0.0
    foreach ($probe in @($client, $server)) {
        if ($null -ne $probe) {
            $times = [WzPerfNative]::Times($probe.Child)
            $own += $times[0] + $times[1]
            Close-Probe $probe
        }
    }
    $result['Own'] = $own
    return $result
}

# Matrix.timed of perf_matrix.py: run until the cell gave figures while the pinned CPUs were used by nothing
# else, up to the plan's runs; a lost run ends the cell at once.
function Invoke-Timed([string]$binary, [string]$transport, [bool]$batching, [string]$workload, [int]$size,
                      [string]$tag) {
    $shares = New-Object System.Collections.Generic.List[string]
    $runs = [int]$script:PlanDoc.max_runs
    for ($run = 0; $run -lt $runs; $run++) {
        $busy0 = Get-CpuBusy
        $clock = [System.Diagnostics.Stopwatch]::StartNew()
        $result = Invoke-CellOnce $binary $transport $batching $workload $size $tag
        $wall = $clock.Elapsed.TotalSeconds
        if ($result.ContainsKey('Lost')) { return @{ Status = 'lost'; Why = $result.Lost } }
        $foreign = [math]::Max(0.0, (Get-CpuBusy) - $busy0 - $result.Own) / ($wall * $script:PinnedCpus.Count)
        if ($foreign -le [double]$script:PlanDoc.foreign_limit) {
            return @{ Status = 'measured'; Figures = $result.Figures; Foreign = $foreign }
        }
        $shares.Add(("{0:F0}%" -f ($foreign * 100)))
        Start-Sleep -Seconds 5
    }
    return @{ Status = 'disturbed'; Why = "the pinned CPUs were used by something else in $runs runs ($($shares -join ', '))" }
}

function Get-NotApplicable([string]$arm, [string]$transport) {
    return Get-Prop $script:PlanDoc.not_applicable "$arm/$transport"
}

function Invoke-MatrixCell([string]$arm, [string]$transport, [bool]$batching, [string]$workload, [int]$size,
                           [int]$rep) {
    $cell = [ordered]@{ arm = $arm; transport = $transport; batching = $batching; workload = $workload; size = $size;
                        rep = $rep }
    $why = Get-NotApplicable $arm $transport
    if ($null -ne $why) {
        $cell['status'] = 'not-applicable'; $cell['why'] = $why; $cell['figures'] = [ordered]@{}
        return $cell
    }
    $mark = if ($batching) { 'b' } else { 'n' }
    $tag = "r$rep-$arm-$transport-$mark-$workload-$size"
    $result = Invoke-Timed "perf_probe_$arm.exe" $transport $batching $workload $size $tag
    if ($result.Status -eq 'measured') {
        $cell['status'] = 'measured'; $cell['figures'] = $result.Figures; $cell['foreign_share'] = $result.Foreign
    } else {
        $cell['status'] = 'lost'; $cell['why'] = $result.Why; $cell['figures'] = [ordered]@{}
        if ($result.Status -eq 'disturbed') { $cell['disturbed'] = $true }
    }
    return $cell
}

# -- the summary, as perf_matrix.py summarizes a run -------------------------------------------------------

function Get-Median($values) {
    $sorted = @($values | Sort-Object)
    $n = $sorted.Count
    if ($n % 2 -eq 1) { return [double]$sorted[($n - 1) / 2] }
    return ([double]$sorted[$n / 2 - 1] + [double]$sorted[$n / 2]) / 2
}

# A figure perf_matrix.numbers keeps: a number, not a flag and not a figure the cell could not give.
function Test-Number($value) { return ($null -ne $value -and $value -isnot [bool] -and $value -is [ValueType]) }

function Get-Summary($cells) {
    $order = @($script:PlanDoc.transports)
    $groups = @{}
    foreach ($cell in $cells) {
        $key = '{0}|{1}|{2}|{3}' -f $cell.transport, $cell.batching, $cell.workload, $cell.size
        if (-not $groups.ContainsKey($key)) {
            $groups[$key] = @{ Transport = $cell.transport; Batching = $cell.batching; Workload = $cell.workload;
                               Size = $cell.size; Arms = @{} }
        }
        $arms = $groups[$key].Arms
        if (-not $arms.ContainsKey($cell.arm)) {
            $arms[$cell.arm] = @{ Figures = New-Object System.Collections.ArrayList; Lost = 0; Status = @{} }
        }
        $arm = $arms[$cell.arm]
        $arm.Status[$cell.status] = $true
        if ($cell.status -eq 'measured') { [void]$arm.Figures.Add($cell.figures) }
        elseif ($cell.status -eq 'lost') { $arm.Lost++ }
    }
    $sorted = @($groups.Values | Sort-Object @{ Expression = { [array]::IndexOf($order, $_.Transport) } },
                                              @{ Expression = { [int]$_.Batching } },
                                              @{ Expression = { $_.Workload } },
                                              @{ Expression = { [int]$_.Size } })
    $rows = New-Object System.Collections.ArrayList
    foreach ($group in $sorted) {
        $arms = [ordered]@{}
        foreach ($name in @($group.Arms.Keys | Sort-Object)) {
            $arm = $group.Arms[$name]
            $names = @($arm.Figures | ForEach-Object { $f = $_; @($f.Keys) | Where-Object { Test-Number $f[$_] } } |
                       Sort-Object -Unique)
            $median = [ordered]@{}
            foreach ($figure in $names) {
                $values = @($arm.Figures | Where-Object { Test-Number $_[$figure] } | ForEach-Object { $_[$figure] })
                $median[$figure] = Get-Median $values
            }
            $arms[$name] = [ordered]@{ measured = $arm.Figures.Count; lost = $arm.Lost;
                                       not_applicable = $arm.Status.ContainsKey('not-applicable'); median = $median }
        }
        $ratio = [ordered]@{}
        if ($arms.Contains('P') -and $arms.Contains('W')) {
            foreach ($figure in @($arms['W'].median.Keys)) {
                $reference = $arms['P'].median[$figure]
                if ($null -ne $reference -and $reference -ne 0) { $ratio[$figure] = $arms['W'].median[$figure] / $reference }
            }
        }
        [void]$rows.Add([ordered]@{ transport = $group.Transport; batching = $group.Batching; workload = $group.Workload;
                                    size = $group.Size; arms = $arms; w_over_p = $ratio })
    }
    return ,$rows
}

function Format-Figure($value, [string]$spec) {
    if ($null -eq $value) { return '-' }
    return ([double]$value).ToString($spec, [System.Globalization.CultureInfo]::InvariantCulture)
}

function Get-ReportLines($rows) {
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($row in $rows) {
        $state = if ($row.batching) { 'on' } else { 'off' }
        $out.Add(("{0} batching={1} {2} {3} B" -f $row.transport, $state, $row.workload, $row.size))
        foreach ($name in @('P', 'W')) {
            if ($row.arms.Contains($name)) {
                $arm = $row.arms[$name]
                $said = if ($arm.not_applicable) { 'not applicable' } else { "$($arm.measured) measured, $($arm.lost) lost" }
                $out.Add("  $($name): $said")
            }
        }
        $names = @($row.arms.Values | ForEach-Object { @($_.median.Keys) } | Sort-Object -Unique)
        foreach ($figure in $names) {
            $p = if ($row.arms.Contains('P')) { Format-Figure $row.arms['P'].median[$figure] 'G4' } else { '-' }
            $w = if ($row.arms.Contains('W')) { Format-Figure $row.arms['W'].median[$figure] 'G4' } else { '-' }
            $r = Format-Figure $row.w_over_p[$figure] 'F3'
            $better = Get-Prop $script:PlanDoc.metrics $figure
            if ($null -eq $better) { $better = '?' }
            $out.Add(("    {0,-22} P {1,12}  W {2,12}  W/P {3,7}  ({4} is better)" -f $figure, $p, $w, $r, $better))
        }
    }
    return ,$out
}

# -- the build -------------------------------------------------------------------------------------------

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

# Batch lines run in the environment 'vcvarsall.bat x64' sets up, each line's output appended to $log; the
# exit status of the first line that failed, or 0.
function Invoke-InVs([string]$name, [string[]]$lines, [string]$log) {
    $bat = Join-Path $script:WorkDir "$name.bat"
    # vcvarsall.bat's own exit status is not its verdict (an optional component it looks for and lacks sets
    # it), so what is asked of it is that cl is then found.
    # VsDevCmd starts a telemetry helper that inherits the redirected handle and keeps the log open, so a
    # later line cannot append to it: the helper is switched off, and the environment's own output goes to
    # a file of its own.
    $text = '@echo off' + $CRLF + 'set VSCMD_SKIP_SENDTELEMETRY=1' + $CRLF + 'call ' + $Q + $script:VcVars + $Q + ' x64 > ' + $Q + $log + '.vcvars' + $Q + ' 2>&1' + $CRLF +
            'where cl >> ' + $Q + $log + $Q + ' 2>&1' + $CRLF + 'if errorlevel 1 exit /b 1' + $CRLF
    foreach ($line in $lines) {
        $text += $line + ' >> ' + $Q + $log + $Q + ' 2>&1' + $CRLF + 'if errorlevel 1 exit /b 1' + $CRLF
    }
    $text += 'exit /b 0' + $CRLF
    [System.IO.File]::WriteAllText($bat, $text, [System.Text.Encoding]::ASCII)
    $null = & cmd.exe /d /c $bat
    return $LASTEXITCODE
}

# The switches pico's generated config.h states, as wz_config.pico_flag_states reads them: those it turns on.
function Get-SwitchesOn([string]$header) {
    $on = @{}
    foreach ($line in ($header -split "\r?\n")) {
        if ($line -match '^\s*#\s*define\s+(Z_FEATURE_[A-Z0-9_]+)\s+([01])\b') {
            if ($Matches[2] -eq '1') { $on[$Matches[1]] = $true }
        } elseif ($line -match '^\s*#\s*define\s+(Z_FEATURE_[A-Z0-9_]+)\s*(?://.*|/\*.*)?$') {
            $on[$Matches[1]] = $true
        }
    }
    return $on
}

# The cache entries of pico's own options and of the build's type, generator and flags, as CMake holds them
# after the configure: what the build was, not what it was asked. None of them names a path of this machine.
function Get-CacheOptions([string]$cache) {
    $out = [ordered]@{}
    $wanted = '^(Z_[A-Z0-9_]+|ZP_[A-Z0-9_]+|ZENOH_[A-Z0-9_]+|BATCH_[A-Z0-9_]+|FRAG_[A-Z0-9_]+|BUILD_SHARED_LIBS|' +
              'BUILD_EXAMPLES|BUILD_TESTING|CMAKE_BUILD_TYPE|CMAKE_GENERATOR|CMAKE_GENERATOR_PLATFORM|CMAKE_C_FLAGS|' +
              'CMAKE_C_FLAGS_RELEASE|CMAKE_SHARED_LINKER_FLAGS|CMAKE_SHARED_LINKER_FLAGS_RELEASE):([A-Z]+)=(.*)$'
    foreach ($line in ($cache -split "\r?\n")) {
        if ($line -match $wanted -and $Matches[2] -ne 'INTERNAL') { $out[$Matches[1]] = $Matches[3] }
    }
    return $out
}

function Reset-Directory([string]$path) {
    if (Test-Path -LiteralPath $path) { Remove-Item -Recurse -Force -LiteralPath $path }
    [void](New-Item -ItemType Directory -Path $path)
}

function Invoke-Build {
    foreach ($given in @(@('-PicoSource', $PicoSource), @('-Package', $Package), @('-Probe', $Probe))) {
        if (-not $given[1] -or -not (Test-Path -LiteralPath $given[1])) { Fail "$($given[0]) names nothing ('$($given[1])')" }
    }
    $picoTree = (Resolve-Path -LiteralPath $PicoSource).Path
    $probeSource = (Resolve-Path -LiteralPath $Probe).Path
    # An archive of the pinned tree (git archive --prefix=zenoh-pico/) is unpacked afresh: pico's configure
    # writes zenoh-pico.h into its source tree.
    if ($picoTree -like '*.zip') {
        $unpackedPico = Join-Path $script:WorkDir 'pico-src'
        Reset-Directory $unpackedPico
        Expand-Archive -LiteralPath $picoTree -DestinationPath $unpackedPico
        $picoTops = @(Get-ChildItem -LiteralPath $unpackedPico -Directory)
        if ($picoTops.Count -ne 1) { Fail "$PicoSource holds not one directory" }
        $picoTree = $picoTops[0].FullName
    }
    if (-not (Test-Path -LiteralPath (Join-Path $picoTree 'CMakeLists.txt'))) { Fail "$picoTree is no zenoh-pico tree (no CMakeLists.txt)" }
    $script:VcVars = Join-Path (Find-VsRoot) 'VC\Auxiliary\Build\vcvarsall.bat'
    if (-not (Test-Path -LiteralPath $script:VcVars)) { Fail "no vcvarsall.bat at $script:VcVars" }
    $cmakeExe = Find-CMake

    # Arm W: the package the plan was made from, and no other.
    $digest = (Get-FileHash -Algorithm SHA256 -LiteralPath $Package).Hash.ToLowerInvariant()
    if ($digest -ne $script:PlanDoc.package.sha256) {
        Fail "$Package is not the package the plan was made from (sha256 $digest, the plan's $($script:PlanDoc.package.sha256))"
    }
    $unpacked = Join-Path $script:WorkDir 'package'
    Reset-Directory $unpacked
    Expand-Archive -LiteralPath $Package -DestinationPath $unpacked
    $tops = @(Get-ChildItem -LiteralPath $unpacked -Directory)
    if ($tops.Count -ne 1) { Fail "$Package is not one package directory" }
    $top = $tops[0].FullName
    $manifest = Get-Content -Raw -LiteralPath (Join-Path $top 'manifest.json') | ConvertFrom-Json
    if ($manifest.target -ne $script:PlanDoc.package.target) { Fail "the package's target $($manifest.target) is not the plan's" }
    Reset-Directory $script:BinDir
    foreach ($library in @($manifest.libraries)) {
        Copy-Item -LiteralPath (Join-Path $top "release\bin\$library.dll") -Destination $script:BinDir
    }

    # Arm P: pico configured as capability_cost_gate.pico_reference_tree configures it, in a fresh tree, since
    # CMake keeps the flags of the first configure of a directory.
    $build = Join-Path $script:WorkDir 'pico-build'
    if (Test-Path -LiteralPath $build) { Remove-Item -Recurse -Force -LiteralPath $build }
    $switches = @($script:PlanDoc.reference_switches.PSObject.Properties | Sort-Object Name)
    $defines = ($switches | ForEach-Object { '-D' + $_.Name + '=' + $_.Value }) -join ' '
    $configure = $Q + $cmakeExe + $Q + ' -S ' + $Q + $picoTree + $Q + ' -B ' + $Q + $build + $Q + ' -G ' + $Q + $Generator + $Q +
                 ' -A x64 -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -DBUILD_EXAMPLES=OFF -DBUILD_TESTING=OFF ' + $defines
    $compile = $Q + $cmakeExe + $Q + ' --build ' + $Q + $build + $Q + ' --config Release --parallel'
    $log = Join-Path $script:WorkDir 'build-reference.log'
    if ((Invoke-InVs 'build-reference' @($configure, $compile) $log) -ne 0) { Fail "the zenoh-pico reference did not build (see $log)" }
    $dll = @(Get-ChildItem -LiteralPath $build -Recurse -Filter 'zenohpico.dll' | Where-Object { $_.FullName -notmatch '\\CMakeFiles\\' })
    $implib = @(Get-ChildItem -LiteralPath $build -Recurse -Filter 'zenohpico.lib' | Where-Object { $_.FullName -notmatch '\\CMakeFiles\\' })
    if ($dll.Count -ne 1 -or $implib.Count -ne 1) {
        Fail "the reference build left $($dll.Count) zenohpico.dll and $($implib.Count) zenohpico.lib under $build, not one of each"
    }
    Copy-Item -LiteralPath $dll[0].FullName -Destination $script:BinDir
    $on = Get-SwitchesOn (Read-Text (Join-Path $build 'include\zenoh-pico\config.h'))
    $refused = @($switches | Where-Object { $on.ContainsKey($_.Name) -ne ([int]$_.Value -ne 0) } |
                 ForEach-Object { $_.Name } | Sort-Object)
    # pico's headers are its source tree's with the config.h its CMake generated on top, as on Linux: a
    # quoted include is looked for beside the including header first, so the tree's own would win otherwise.
    $includeP = Join-Path $script:WorkDir 'include-P'
    if (Test-Path -LiteralPath $includeP) { Remove-Item -Recurse -Force -LiteralPath $includeP }
    Copy-Item -Recurse -LiteralPath (Join-Path $picoTree 'include') -Destination $includeP
    Copy-Item -Recurse -Force -Path (Join-Path $build 'include\*') -Destination $includeP

    # The probe against each arm with the same words. /MD: both libraries link the C runtime as a DLL.
    $cl = 'cl /nologo /std:c11 /experimental:c11atomics /O2 /MD /DZENOH_WINDOWS'
    $arms = @(
        @{ Arm = 'P'; Include = $includeP; Libraries = @($implib[0].FullName) },
        @{ Arm = 'W'; Include = (Join-Path $top 'include');
           Libraries = @(@($manifest.libraries) | ForEach-Object { Join-Path $top "release\lib\$_.lib" }) }
    )
    foreach ($arm in $arms) {
        $objects = Join-Path $script:WorkDir "obj-$($arm.Arm)"
        Reset-Directory $objects
        $libraries = ($arm.Libraries | ForEach-Object { $Q + $_ + $Q }) -join ' '
        $exe = Join-Path $script:BinDir "perf_probe_$($arm.Arm).exe"
        $line = $cl + ' /I' + $Q + $arm.Include + $Q + ' ' + $Q + $probeSource + $Q + ' ' + $libraries +
                ' ws2_32.lib psapi.lib /Fo:' + $Q + (Join-Path $objects 'perf_probe.obj') + $Q + ' /Fe:' + $Q + $exe + $Q
        $log = Join-Path $script:WorkDir "build-probe-$($arm.Arm).log"
        if ((Invoke-InVs "build-probe-$($arm.Arm)" @($line) $log) -ne 0) { Fail "perf_probe against arm $($arm.Arm) did not build (see $log)" }
    }

    # The toolchain, in the words the record gives it: cl's banner (it exits non-zero with no input) and CMake's.
    $versionLog = Join-Path $script:WorkDir 'toolchain.log'
    [void](Invoke-InVs 'toolchain' @(('"' + $cmakeExe + '" --version'), 'cl') $versionLog)
    $said = @((Read-Text $versionLog) -split "\r?\n")
    $compiler = @($said | Where-Object { $_ -match '^Microsoft \(R\) C/C\+\+' } | Select-Object -First 1)
    $maker = @($said | Where-Object { $_ -match '^cmake version' } | Select-Object -First 1)
    $record = [ordered]@{
        reference_pin = $script:PlanDoc.reference_pin
        reference_toolchain = ('{0}; {1}; generator {2} x64' -f "$compiler".Trim(), "$maker".Trim(), $Generator)
        reference_switches = $script:PlanDoc.reference_switches
        reference_refused = $refused
        reference_cache = Get-CacheOptions (Read-Text (Join-Path $build 'CMakeCache.txt'))
        # build_normalization.py's rule (prefix maps and the commit's epoch in the C flags) is GCC's; MSVC takes
        # none of its words, so the reference here is built without it.
        reference_build_rule = 'none: the Linux build rule (build_normalization.py) has no MSVC counterpart'
        probe_compile = "$cl ws2_32.lib psapi.lib"
        wz_features = $script:PlanDoc.wz_features
        wz_engine = $script:PlanDoc.wz_engine
        wz_package = $script:PlanDoc.package
    }
    Write-Text (Join-Path $script:WorkDir 'reference.json') ($record | ConvertTo-Json -Depth 12)
    $pin = "$($script:PlanDoc.reference_pin)"
    Say ('reference zenoh-pico {0} as the same build ({1}); {2} switches set from the plan' -f
         $pin.Substring(0, [math]::Min(12, $pin.Length)), $record.reference_toolchain, $switches.Count)
    if ($refused.Count -gt 0) {
        Say "pico built $($refused -join ', ') otherwise than asked, so the two builds differ there (reference.json says so)"
    }
    Say "arm W: $($script:PlanDoc.package.name) on the $($script:PlanDoc.wz_engine) engine"
}

# -- the run ---------------------------------------------------------------------------------------------

function Get-DefaultGroupAdapter {
    $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric |
             Select-Object -First 1
    if ($null -eq $route) { return $null }
    return Get-NetAdapter -InterfaceIndex $route.ifIndex -ErrorAction SilentlyContinue
}

# Whether an arm forms the group: a short round trip of each arm on it, before the matrix. Both failing is
# the host's, which only this tells apart from an arm's own failure.
function Test-Group {
    $said = New-Object System.Collections.Generic.List[string]
    $formed = $false
    foreach ($arm in @('P', 'W')) {
        if ($null -ne (Get-NotApplicable $arm 'multicast')) { continue }
        $endpoints = Get-Endpoints 'multicast'
        $tag = "preflight-$arm-multicast"
        $server = Start-ProbeProcess "perf_probe_$arm.exe" 'pong' (@('-m', 'peer') + $endpoints.Server) 'server' $tag
        $client = $null
        try {
            Start-Sleep -Milliseconds ([int]([double]$script:PlanDoc.settle_s * 1000))
            $client = Start-ProbeProcess "perf_probe_$arm.exe" 'ping' (@('-m', 'peer') + $endpoints.Client +
                @('-s', '8', '-n', '200', '-w', '500', '-o', "$TimeoutMs")) 'client' $tag
            [void](Wait-Probe $client ([double]$script:PlanDoc.ready_s + 30))
        } finally {
            if ($null -ne $client) { Stop-Probe $client }
            Stop-Probe $server
        }
        $text = Read-Text $client.Out
        $ping = Get-Fields $text 'ping' $script:PlanDoc.line_keys.ping
        if ($null -ne $ping -and [long]$ping['round_trips'] -gt 0) { $formed = $true }
        $said.Add("arm $($arm): $(Get-LastWords $text)")
        Close-Probe $client
        Close-Probe $server
    }
    return @{ Formed = $formed; Said = ($said -join '; ') }
}

function Get-HostRecord {
    $version = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $cpu = (Get-ItemProperty 'HKLM:\HARDWARE\DESCRIPTION\System\CentralProcessor\0').ProcessorNameString
    $display = Get-Prop $version 'DisplayVersion'
    $kernel = '{0}.{1} ({2})' -f [Environment]::OSVersion.Version.ToString(3), (Get-Prop $version 'UBR'), $display
    return @{ Kernel = $kernel; Cpu = "$cpu".Trim() }
}

function Invoke-PlannedCell($spec, [bool]$again, [string]$log) {
    $cell = Invoke-MatrixCell $spec.Arm $spec.Transport $spec.Batching $spec.Workload $spec.Size $spec.Rep
    if ($again) { $cell['second_pass'] = $true }
    [System.IO.File]::AppendAllText($log, ($cell | ConvertTo-Json -Depth 12 -Compress) + $LF, $Utf8)
    if ($cell.Contains('why')) {
        $shown = $cell['why']
    } else {
        $shown = (@('cpu_ns_per_msg', 'msgs_per_s', 'rtt_p50_us', 'rtt_p99_us') |
                  Where-Object { $cell['figures'].Contains($_) -and $null -ne $cell['figures'][$_] } |
                  ForEach-Object { "$_ $(Format-Figure $cell['figures'][$_] 'G4')" }) -join ', '
    }
    $prefix = if ($again) { 'again ' } else { '' }
    $mode = if ($spec.Batching) { 'on' } else { 'off' }
    [Console]::Out.WriteLine("  $($prefix)r$($spec.Rep) $($spec.Arm) $($spec.Transport) batching=$mode $($spec.Workload) $($spec.Size) B: $($cell['status']): $shown")
    return $cell
}

function Invoke-Run {
    $reference = Join-Path $script:WorkDir 'reference.json'
    if (-not (Test-Path -LiteralPath $reference)) { Fail "$reference is not there: run -Mode build first" }
    $builds = Get-Content -Raw -LiteralPath $reference | ConvertFrom-Json
    foreach ($arm in @('P', 'W')) {
        if (-not (Test-Path -LiteralPath (Join-Path $script:BinDir "perf_probe_$arm.exe"))) { Fail "$script:BinDir lacks perf_probe_$arm.exe" }
    }
    $transportList = Get-Words $Transports
    $workloadList = Get-Words $Workloads
    $batchings = Get-Words $Batching
    # Get-Words hands its list back as one object (the unary comma), so the pipeline would see the array.
$sizeList = @(foreach ($w in (Get-Words $Sizes)) { [int]$w })
    $unknown = @($transportList | Where-Object { @($script:PlanDoc.transports) -notcontains $_ }) +
               @($workloadList | Where-Object { @($script:PlanDoc.workloads) -notcontains $_ }) +
               @($batchings | Where-Object { @('off', 'on') -notcontains $_ })
    if ($unknown.Count -gt 0 -or $transportList.Count -eq 0 -or $workloadList.Count -eq 0 -or $batchings.Count -eq 0 -or
        $sizeList.Count -eq 0) {
        [Console]::Out.WriteLine("perf-matrix-windows: unknown or empty selection $($unknown -join ', ')")
        exit 64
    }
    if (($sizeList | Measure-Object -Minimum).Minimum -lt 8) {
        [Console]::Out.WriteLine("perf-matrix-windows: a payload is at least 8 bytes (the round trip's sequence number)")
        exit 64
    }
    $notMeasured = [ordered]@{}
    foreach ($transport in $transportList) {
        $why = Get-Prop $script:PlanDoc.not_run $transport
        if ($null -ne $why) { $notMeasured[$transport] = $why }
    }
    $transportList = @($transportList | Where-Object { -not $notMeasured.Contains($_) })

    $client = Get-CpuList $ClientCpus
    $server = Get-CpuList $ServerCpus
    $shared = @($client | Where-Object { $server -contains $_ })
    if ($shared.Count -gt 0) { Fail "the client side and the server side share CPU(s) $($shared -join ',')" }
    $count = [Environment]::ProcessorCount
    $beyond = @(@($client) + @($server) | Where-Object { $_ -ge $count -or $_ -ge 64 })
    if ($beyond.Count -gt 0) { Fail "CPU(s) $($beyond -join ',') are not among this host's $count" }
    $script:ClientMask = Get-Mask $client
    $script:ServerMask = Get-Mask $server
    $script:PinnedCpus = @(@($client) + @($server) | Sort-Object -Unique)
    $coreOf = [WzPerfNative]::CoreOf()
    $cores = [ordered]@{}
    foreach ($cpu in $script:PinnedCpus) { $cores["$cpu"] = $coreOf[$cpu] }

    $script:RunDir = Join-Path $script:WorkDir ('runs\windows-' + (Get-UtcText 'yyyyMMdd\THHmmss'))
    [void](New-Item -ItemType Directory -Path $script:RunDir)
    $groupRecord = $null
    $started = Get-UtcText "yyyy-MM-dd'T'HH:mm:ss'Z'"
    try {
        if ($transportList -contains 'multicast') {
            if ($GroupInterface) {
                $adapter = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceGuid -eq $GroupInterface } |
                           Select-Object -First 1
            } else {
                $adapter = Get-DefaultGroupAdapter
            }
            if ($null -eq $adapter) {
                $notMeasured['multicast'] = 'no adapter to join the group on: the host has no default route, and -GroupInterface names none'
            } else {
                $script:GroupGuid = $adapter.InterfaceGuid
                $groupRecord = [ordered]@{ guid = $adapter.InterfaceGuid; adapter = $adapter.InterfaceDescription }
                $group = Test-Group
                if (-not $group.Formed) {
                    $notMeasured['multicast'] = ('neither arm formed the group {0} on the adapter {1} in a short round trip ' +
                        '({2}): the host does not carry a group to its own members there, by its adapter or by a firewall ' +
                        'that drops the datagrams; no firewall rule was read or changed') -f $script:PlanDoc.group,
                        $adapter.InterfaceDescription, $group.Said
                }
            }
            if ($notMeasured.Contains('multicast')) { $transportList = @($transportList | Where-Object { $_ -ne 'multicast' }) }
        }
        foreach ($entry in $notMeasured.GetEnumerator()) { Say "$($entry.Key) NOT-MEASURED: $($entry.Value)" }
        if ($transportList.Count -eq 0) { Fail 'no transport is left to measure' }

        $hostRecord = Get-HostRecord
        $record = [ordered]@{
            tree = $script:PlanDoc.tree; tree_dirty = $script:PlanDoc.tree_dirty
            host = $env:COMPUTERNAME; kernel = $hostRecord.Kernel; cpu = $hostRecord.Cpu; threads = $count
            cc = ($builds.reference_toolchain -split '; ')[0]; rustc = $script:PlanDoc.package.rustc
            client_cpus = $ClientCpus; server_cpus = $ServerCpus; reps = $Reps; sizes = $Sizes; pings = $Pings
            warmup_ms = $WarmupMs; window_s = $WindowS; timeout_ms = $TimeoutMs
            foreign_limit = $script:PlanDoc.foreign_limit
            platform = $script:PlanDoc.platform
            builds = $builds
            engine = $builds.wz_engine
            external = [ordered]@{ status = 'not-measured'; why = 'arm X, an external library of the pico API, is run by the Linux runner alone' }
            not_measured = $notMeasured
            group_interface = $groupRecord
            cores = $cores
            started = $started
        }
        $arms = @('P', 'W')
        $schedule = New-Object System.Collections.ArrayList
        for ($rep = 1; $rep -le $Reps; $rep++) {
            foreach ($transport in $transportList) { foreach ($batching in $batchings) { foreach ($size in $sizeList) {
                foreach ($workload in $workloadList) {
                    $order = if ($rep % 2 -eq 1) { $arms } else { @($arms[1], $arms[0]) }
                    foreach ($arm in $order) {
                        [void]$schedule.Add(@{ Rep = $rep; Transport = $transport; Batching = ($batching -eq 'on'); Size = $size;
                                           Workload = $workload; Arm = $arm })
                    }
                }
            } } }
        }
        Say ('{0} repetition(s) of {1} x batching {2} x {3} x {4} B, arms P, W; client side on {5}, server side on {6}; arm W on the {7} engine' -f
             $Reps, ($transportList -join ', '), ($batchings -join ', '), ($workloadList -join ', '), ($sizeList -join ', '),
             $ClientCpus, $ServerCpus, $record.engine)
        $log = Join-Path $script:RunDir 'cells.jsonl'
        Write-Text $log ''
        $cells = New-Object System.Collections.ArrayList
        foreach ($spec in $schedule) { [void]$cells.Add((Invoke-PlannedCell $spec $false $log)) }
        # A host is busy in stretches: a cell disturbed in every run of its first turn is run once more at the
        # end, and the later result is the cell's.
        $deferred = @(for ($i = 0; $i -lt $cells.Count; $i++) {
            if ($cells[$i]['status'] -eq 'lost' -and $cells[$i].Contains('disturbed')) { $i }
        })
        if ($deferred.Count -gt 0) { Say "$($deferred.Count) cell(s) were disturbed by the host; one more pass over them" }
        foreach ($index in $deferred) { $cells[$index] = Invoke-PlannedCell $schedule[$index] $true $log }
    } finally {
        Stop-Live
    }
    $record['finished'] = Get-UtcText "yyyy-MM-dd'T'HH:mm:ss'Z'"
    $rows = Get-Summary $cells
    $doc = [ordered]@{ schema = $script:PlanDoc.schema_of_result; record = $record; metrics = $script:PlanDoc.metrics;
                       cells = $cells; summary = $rows }
    Write-Text (Join-Path $script:RunDir 'perf.json') (($doc | ConvertTo-Json -Depth 12) + $LF)
    Write-Text (Join-Path $script:RunDir 'report.txt') (((Get-ReportLines $rows) -join $LF) + $LF)
    $measured = @($cells | Where-Object { $_['status'] -eq 'measured' }).Count
    $lost = @($cells | Where-Object { $_['status'] -eq 'lost' }).Count
    $na = @($cells | Where-Object { $_['status'] -eq 'not-applicable' }).Count
    Say "$measured measured, $lost lost, $na not applicable; $(Join-Path $script:RunDir 'perf.json')"
}

# -- idle CPUs -------------------------------------------------------------------------------------------

function Invoke-IdleCpus {
    $first = [WzPerfNative]::Sample()
    Start-Sleep -Milliseconds ([int]($IdleSeconds * 1000))
    $second = [WzPerfNative]::Sample()
    $coreOf = [WzPerfNative]::CoreOf()
    $busy = @{}
    for ($cpu = 0; $cpu -lt $second[0].Count; $cpu++) {
        $whole = $second[1][$cpu] - $first[1][$cpu]
        $busy[$cpu] = if ($whole -gt 0) { ($second[0][$cpu] - $first[0][$cpu]) / $whole } else { 1.0 }
        [Console]::Out.WriteLine(('  cpu{0,-3} core {1,-3} busy {2,5:F1}%' -f $cpu, $coreOf[$cpu], ($busy[$cpu] * 100)))
    }
    # suggest_pinning of perf_matrix.py: whole cores, a core as busy as its busiest CPU, the least busy first.
    $cores = @{}
    foreach ($cpu in @($busy.Keys)) {
        $core = $coreOf[$cpu]
        if ($core -lt 0) { continue }
        if (-not $cores.ContainsKey($core)) { $cores[$core] = New-Object System.Collections.Generic.List[int] }
        $cores[$core].Add($cpu)
    }
    $ranked = New-Object System.Collections.ArrayList
    $byBusy = @($cores.Values | Sort-Object @{ Expression = { ($_ | ForEach-Object { $busy[$_] } | Measure-Object -Maximum).Maximum } },
                                             @{ Expression = { ($_ | Measure-Object -Minimum).Minimum } })
    foreach ($entry in $byBusy) { [void]$ranked.Add($entry) }
    $sides = New-Object System.Collections.Generic.List[string]
    for ($s = 0; $s -lt 2; $s++) {
        $side = New-Object System.Collections.Generic.List[int]
        while ($ranked.Count -gt 0 -and $side.Count -lt $PerSide) {
            foreach ($cpu in $ranked[0]) { $side.Add($cpu) }
            $ranked.RemoveAt(0)
        }
        if ($side.Count -lt $PerSide) {
            [Console]::Out.WriteLine("perf-matrix-windows: this host has too few cores for two sides of $PerSide CPUs")
            exit 1
        }
        $sides.Add((@($side | Sort-Object) -join ','))
    }
    [Console]::Out.WriteLine("-ClientCpus $($sides[0]) -ServerCpus $($sides[1])")
}

# -- the modes -------------------------------------------------------------------------------------------

if ($Mode -eq 'idle-cpus') {
    Invoke-IdleCpus
    exit 0
}
if (-not $Plan -or -not (Test-Path -LiteralPath $Plan)) { Fail "-Plan names no plan ('$Plan'); make one with perf_matrix.py windows-plan" }
if (-not $Work) { Fail '-Work names no directory' }
$script:PlanDoc = Get-Content -Raw -LiteralPath $Plan | ConvertFrom-Json
if ($script:PlanDoc.schema -ne 'wz-pico-perf-windows-plan/1') { Fail "$Plan is not a plan of schema wz-pico-perf-windows-plan/1" }
if (-not (Test-Path -LiteralPath $Work)) { [void](New-Item -ItemType Directory -Path $Work) }
$script:WorkDir = (Resolve-Path -LiteralPath $Work).Path
$script:BinDir = Join-Path $script:WorkDir 'bin'
if ($Mode -eq 'all' -or $Mode -eq 'build') { Invoke-Build }
if ($Mode -eq 'all' -or $Mode -eq 'run') { Invoke-Run }
exit 0
