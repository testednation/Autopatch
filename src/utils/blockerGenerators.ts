import { ScannedBinaryFile, TelemetryFinding } from './binaryScanner';

export interface DomainSummaryItem {
  domain: string;
  vendor: string;
  category: string;
  severity: string;
  occurrences: number;
  selectedOccurrences: number;
  selected: boolean;
  files: string[];
  findings: TelemetryFinding[];
}

/**
 * Aggregates all unique domains across scanned files, tracking both total occurrences
 * and currently selected (active) occurrences so toggling findings updates outputs in real time.
 */
export function aggregateUniqueDomains(
  files: ScannedBinaryFile[],
  onlySelected = false
): DomainSummaryItem[] {
  const map = new Map<string, DomainSummaryItem>();

  for (const file of files) {
    for (const f of file.findings) {
      if (onlySelected && !f.selected) continue;

      const existing = map.get(f.domain);
      if (existing) {
        existing.occurrences += 1;
        if (f.selected) existing.selectedOccurrences += 1;
        existing.selected = existing.selectedOccurrences > 0;
        if (!existing.files.includes(file.name)) {
          existing.files.push(file.name);
        }
        existing.findings.push(f);
      } else {
        map.set(f.domain, {
          domain: f.domain,
          vendor: f.vendor,
          category: f.category,
          severity: f.severity,
          occurrences: 1,
          selectedOccurrences: f.selected ? 1 : 0,
          selected: f.selected,
          files: [file.name],
          findings: [f],
        });
      }
    }
  }

  return Array.from(map.values()).sort((a, b) => b.occurrences - a.occurrences);
}

/**
 * Generates a formatted /etc/hosts or C:\Windows\System32\drivers\etc\hosts blocklist
 * reflecting only currently selected (active) findings in real time.
 */
export function generateHostsFileBlocklist(
  files: ScannedBinaryFile[],
  redirectIp: '0.0.0.0' | '127.0.0.1' = '0.0.0.0',
  includeIpv6 = true,
  includeComments = true
): string {
  const allDomains = aggregateUniqueDomains(files, false);
  const activeDomains = allDomains.filter((d) => d.selectedOccurrences > 0);
  const skippedCount = allDomains.length - activeDomains.length;
  const timestamp = new Date().toISOString().split('T')[0];

  if (activeDomains.length === 0) {
    return [
      '# ============================================================================',
      `# NullRoute Live Hosts Preview — ${timestamp}`,
      '# No active telemetry findings selected.',
      '# Toggle one or more findings on the left to populate the hosts blocklist.',
      '# ============================================================================',
    ].join('\n');
  }

  const lines: string[] = [
    '# ============================================================================',
    `# NullRoute Offline Telemetry Hosts Blocklist — Generated ${timestamp}`,
    `# Active Blocked Domains: ${activeDomains.length} of ${allDomains.length} (${skippedCount} excluded)`,
    '# Windows Path: C:\\Windows\\System32\\drivers\\etc\\hosts',
    '# Linux/macOS/Android (AdAway/Magisk) Path: /etc/hosts or /system/etc/hosts',
    '# ============================================================================',
    '',
  ];

  for (const item of activeDomains) {
    const activeFiles = Array.from(
      new Set(item.findings.filter((f) => f.selected).map((f) => f.fileName))
    );
    if (includeComments) {
      lines.push(
        `# [${item.category}] ${item.vendor} — Active in: ${activeFiles.join(', ')} (${item.selectedOccurrences}/${item.occurrences} offsets)`
      );
    }
    lines.push(`${redirectIp} ${item.domain}`);
    if (includeIpv6) {
      lines.push(`::0 ${item.domain}`);
    }
    if (includeComments) {
      lines.push('');
    }
  }

  return lines.join('\n').trimEnd() + '\n';
}

/**
 * Generates an Android APK Re-Signing & ADB / AdAway / RethinkDNS Telemetry Blocker script.
 */
export function generateAndroidApkAndAdbBlocker(
  files: ScannedBinaryFile[],
  redirectIp: '0.0.0.0' | '127.0.0.1' = '0.0.0.0'
): string {
  const activeDomains = aggregateUniqueDomains(files, true);
  const apkFiles = files.filter((f) => f.isAPK || f.name.toLowerCase().endsWith('.apk'));

  const lines: string[] = [
    '#!/usr/bin/env bash',
    '# ============================================================================',
    '# NullRoute — Android APK Re-Signing, ADB Telemetry Disable & AdAway Blocklist',
    '# ============================================================================',
    '',
    '# --- Step 1: Zipalign & Re-Sign Patched Android APK(s) (Android SDK Build-Tools) ---',
    '# Note: NullRoute automatically updates DEX Adler-32/SHA-1 and ZIP CRC-32 checksums.',
    '# Re-sign the downloaded APK with apksigner before installing on a device:',
  ];

  if (apkFiles.length > 0) {
    for (const apk of apkFiles) {
      const base = apk.name.replace(/\.apk$/i, '');
      lines.push(`zipalign -p -f -v 4 "${apk.name}" "${base}-aligned.apk"`);
      lines.push(
        `apksigner sign --ks ~/.android/debug.keystore --ks-pass pass:android --out "${base}-signed.apk" "${base}-aligned.apk"`
      );
      lines.push(`adb install -r "${base}-signed.apk"`);
      lines.push('');
    }
  } else {
    lines.push('# zipalign -p -f -v 4 patched.apk patched-aligned.apk');
    lines.push(
      '# apksigner sign --ks ~/.android/debug.keystore --ks-pass pass:android --out patched-signed.apk patched-aligned.apk'
    );
    lines.push('');
  }

  lines.push('# --- Step 2: ADB Non-Root Telemetry Receiver & Background Data Lockdown ---');
  lines.push('# Replace com.example.app with target APK package name:');
  lines.push('PKG="com.example.app"');
  lines.push(
    'adb shell pm disable-user --user 0 "$PKG/com.google.firebase.iid.FirebaseInstanceIdReceiver" 2>/dev/null || true'
  );
  lines.push(
    'adb shell pm disable-user --user 0 "$PKG/com.google.android.gms.measurement.AppMeasurementReceiver" 2>/dev/null || true'
  );
  lines.push(
    'adb shell pm disable-user --user 0 "$PKG/com.google.android.gms.measurement.AppMeasurementService" 2>/dev/null || true'
  );
  lines.push(
    'adb shell pm disable-user --user 0 "$PKG/com.appsflyer.SingleInstallBroadcastReceiver" 2>/dev/null || true'
  );
  lines.push('adb shell cmd netpolicy set restrict-background true');
  lines.push('');
  lines.push(
    `# --- Step 3: AdAway / RethinkDNS / Blokada / Magisk Systemless Hosts (${activeDomains.length} Domains) ---`
  );
  for (const d of activeDomains) {
    lines.push(`${redirectIp} ${d.domain}`);
  }

  return lines.join('\n');
}

/**
 * Generates an elevated Windows PowerShell script that blocks outbound connections
 * from binaries with active selected findings and appends selected domains to the Windows hosts file.
 */
export function generateWindowsFirewallPowerShell(
  files: ScannedBinaryFile[],
  redirectIp: '0.0.0.0' | '127.0.0.1' = '0.0.0.0'
): string {
  const activeDomains = aggregateUniqueDomains(files, true);
  const filesWithSelectedTelemetry = files.filter((f) =>
    f.findings.some((finding) => finding.selected)
  );

  const lines: string[] = [
    '#Requires -RunAsAdministrator',
    '# ============================================================================',
    '# NullRoute — Offline Windows Firewall & Hosts Telemetry Blocker',
    '# Run in an elevated PowerShell prompt (Run as Administrator)',
    '# ============================================================================',
    '$ErrorActionPreference = "Stop"',
    '',
    'Write-Host "Applying NullRoute Outbound Telemetry Rules..." -ForegroundColor Cyan',
    '',
    '# 1. Block Outbound Network Access for Binaries with Selected Telemetry Findings',
  ];

  if (filesWithSelectedTelemetry.length === 0) {
    lines.push('# No executables with active selected telemetry findings.');
  } else {
    for (const file of filesWithSelectedTelemetry) {
      const activeCount = file.findings.filter((x) => x.selected).length;
      const safeRuleName = `NullRoute_Block_${file.name.replace(/[^a-zA-Z0-9._-]/g, '_')}`;
      lines.push(`$ExePath = Join-Path $PSScriptRoot "${file.relativePath.replace(/\//g, '\\')}"`);
      lines.push(`if (Test-Path $ExePath) {`);
      lines.push(
        `    Remove-NetFirewallRule -DisplayName "${safeRuleName}" -ErrorAction SilentlyContinue`
      );
      lines.push(`    New-NetFirewallRule -DisplayName "${safeRuleName}" \``);
      lines.push(`        -Direction Outbound \``);
      lines.push(`        -Program $ExePath \``);
      lines.push(`        -Action Block \``);
      lines.push(`        -Profile Any \``);
      lines.push(
        `        -Description "Blocks ${activeCount} selected telemetry endpoints detected by NullRoute" | Out-Null`
      );
      lines.push(`    Write-Host "  [+] Blocked outbound traffic for: ${file.name}" -ForegroundColor Green`);
      lines.push(`} else {`);
      lines.push(
        `    Write-Host "  [!] Place script in application root folder to block: ${file.relativePath}" -ForegroundColor Yellow`
      );
      lines.push(`}`);
      lines.push('');
    }
  }

  lines.push('# 2. Sinkhole Selected Telemetry Domains in Windows Hosts File');
  lines.push('$HostsPath = "$env:SystemRoot\\System32\\drivers\\etc\\hosts"');
  lines.push('$HostsContent = Get-Content -Path $HostsPath -Raw -ErrorAction SilentlyContinue');
  lines.push('if ($null -eq $HostsContent) { $HostsContent = "" }');
  lines.push('$DomainsToBlock = @(');
  for (const d of activeDomains) {
    lines.push(`    "${d.domain}"`);
  }
  lines.push(')');
  lines.push('');
  lines.push('$AddedCount = 0');
  lines.push('foreach ($Domain in $DomainsToBlock) {');
  lines.push('    if ($HostsContent -notmatch [regex]::Escape($Domain)) {');
  lines.push(`        Add-Content -Path $HostsPath -Value "${redirectIp} $Domain # NullRoute"`);
  lines.push('        $AddedCount++');
  lines.push('    }');
  lines.push('}');
  lines.push('ipconfig /flushdns | Out-Null');
  lines.push(
    'Write-Host "Done. Added $AddedCount telemetry domains to hosts and flushed DNS cache." -ForegroundColor Cyan'
  );

  return lines.join('\n');
}

/**
 * Generates Linux dnsmasq / nftables / Pi-hole / AdGuard Home block rules for selected findings.
 */
export function generateLinuxAndDnsBlocker(files: ScannedBinaryFile[]): string {
  const domains = aggregateUniqueDomains(files, true);

  const lines: string[] = [
    '# ============================================================================',
    `# NullRoute — Linux / dnsmasq / AdGuard Home / Pi-hole Rules (${domains.length} active domains)`,
    '# ============================================================================',
    '',
    '# --- Option A: AdGuard Home / uBlock / Pi-hole Adblock Syntax ---',
  ];

  for (const d of domains) {
    lines.push(`||${d.domain}^`);
  }

  lines.push('');
  lines.push('# --- Option B: dnsmasq (/etc/dnsmasq.d/nullroute-telemetry.conf) ---');
  for (const d of domains) {
    lines.push(`address=/${d.domain}/0.0.0.0`);
    lines.push(`address=/${d.domain}/::`);
  }

  return lines.join('\n');
}

/**
 * Generates a macOS Little Snitch Rule Group (.lsrules JSON) file for selected findings.
 */
export function generateLittleSnitchRules(files: ScannedBinaryFile[]): string {
  const domains = aggregateUniqueDomains(files, true);
  const ruleGroup = {
    name: 'NullRoute Binary Telemetry Blocklist',
    description: `Offline binary audit blocklist covering ${domains.length} selected telemetry domains across ${files.length} scanned files.`,
    rules: domains.map((d) => ({
      action: 'deny',
      direction: 'outgoing',
      priority: 'regular',
      process: 'any',
      'remote-domains': d.domain,
      notes: `[${d.category}] ${d.vendor} — Active in ${d.files.join(', ')}`,
    })),
  };

  return JSON.stringify(ruleGroup, null, 2);
}
