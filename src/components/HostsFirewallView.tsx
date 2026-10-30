import React, { useMemo, useState } from 'react';
import {
  ArrowDownToLine,
  Check,
  ChevronDown,
  ChevronRight,
  Copy,
  Eye,
  FileText,
  ShieldAlert,
  Terminal,
} from 'lucide-react';
import { ScannedBinaryFile } from '../utils/binaryScanner';
import {
  aggregateUniqueDomains,
  generateAndroidApkAndAdbBlocker,
  generateHostsFileBlocklist,
  generateLinuxAndDnsBlocker,
  generateLittleSnitchRules,
  generateWindowsFirewallPowerShell,
} from '../utils/blockerGenerators';

interface HostsFirewallViewProps {
  files: ScannedBinaryFile[];
  onToggleFindingSelection: (fileId: string, findingId: string) => void;
  onToggleDomainSelection: (domain: string, selected: boolean) => void;
  onSetAllFindingsSelected: (selected: boolean) => void;
}

type BlockerFormat = 'android_adb' | 'powershell' | 'linux_dns' | 'littlesnitch' | 'hosts';

export const HostsFirewallView: React.FC<HostsFirewallViewProps> = ({
  files,
  onToggleFindingSelection,
  onToggleDomainSelection,
  onSetAllFindingsSelected,
}) => {
  const [format, setFormat] = useState<BlockerFormat>('android_adb');
  const [redirectIp, setRedirectIp] = useState<'0.0.0.0' | '127.0.0.1'>('0.0.0.0');
  const [includeIpv6, setIncludeIpv6] = useState(true);
  const [includeComments, setIncludeComments] = useState(true);
  const [copiedHosts, setCopiedHosts] = useState(false);
  const [copiedAux, setCopiedAux] = useState(false);
  const [expandedDomains, setExpandedDomains] = useState<Record<string, boolean>>({});
  const [filterQuery, setFilterQuery] = useState('');

  const uniqueDomains = useMemo(() => aggregateUniqueDomains(files, false), [files]);

  const filteredDomains = useMemo(() => {
    const q = filterQuery.trim().toLowerCase();
    if (!q) return uniqueDomains;
    return uniqueDomains.filter(
      (d) =>
        d.domain.toLowerCase().includes(q) ||
        d.vendor.toLowerCase().includes(q) ||
        d.category.toLowerCase().includes(q) ||
        d.files.some((f) => f.toLowerCase().includes(q))
    );
  }, [uniqueDomains, filterQuery]);

  const activeDomainsCount = useMemo(
    () => uniqueDomains.filter((d) => d.selectedOccurrences > 0).length,
    [uniqueDomains]
  );

  const totalFindingsCount = useMemo(
    () => files.reduce((acc, f) => acc + f.findings.length, 0),
    [files]
  );

  const selectedFindingsCount = useMemo(
    () => files.reduce((acc, f) => acc + f.findings.filter((x) => x.selected).length, 0),
    [files]
  );

  // Real-time generated Hosts file content (always live)
  const liveHostsContent = useMemo(
    () => generateHostsFileBlocklist(files, redirectIp, includeIpv6, includeComments),
    [files, redirectIp, includeIpv6, includeComments]
  );

  const liveHostsLines = useMemo(() => liveHostsContent.split('\n'), [liveHostsContent]);

  // Auxiliary firewall/DNS script when user switches format tab
  const generatedFormatOutput = useMemo(() => {
    if (format === 'hosts') return liveHostsContent;
    if (format === 'android_adb') {
      return generateAndroidApkAndAdbBlocker(files, redirectIp);
    }
    if (format === 'powershell') {
      return generateWindowsFirewallPowerShell(files, redirectIp);
    }
    if (format === 'linux_dns') {
      return generateLinuxAndDnsBlocker(files);
    }
    return generateLittleSnitchRules(files);
  }, [files, format, redirectIp, liveHostsContent]);

  const handleCopyHosts = async () => {
    try {
      await navigator.clipboard.writeText(liveHostsContent);
      setCopiedHosts(true);
      setTimeout(() => setCopiedHosts(false), 1800);
    } catch {
      // Fallback
    }
  };

  const handleCopyFormatOutput = async () => {
    try {
      await navigator.clipboard.writeText(generatedFormatOutput);
      setCopiedAux(true);
      setTimeout(() => setCopiedAux(false), 1800);
    } catch {
      // Fallback
    }
  };

  const handleDownloadHosts = () => {
    const blob = new Blob([liveHostsContent], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'hosts';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleDownloadFormat = () => {
    let filename = 'hosts-telemetry-block.txt';
    let mime = 'text/plain;charset=utf-8';

    if (format === 'android_adb') {
      filename = 'Android-APK-Sign-And-Block.sh';
    } else if (format === 'powershell') {
      filename = 'Block-Telemetry.ps1';
    } else if (format === 'linux_dns') {
      filename = 'nullroute-dnsmasq-adguard.conf';
    } else if (format === 'littlesnitch') {
      filename = 'NullRoute-Telemetry.lsrules';
      mime = 'application/json;charset=utf-8';
    }

    const blob = new Blob([generatedFormatOutput], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const toggleExpandDomain = (domain: string) => {
    setExpandedDomains((prev) => ({ ...prev, [domain]: !prev[domain] }));
  };

  return (
    <div className="space-y-6">
      {/* Top Configuration & Real-Time Status Bar */}
      <div className="flex flex-wrap items-center justify-between gap-4 p-4 bg-slate-900 border border-slate-800 rounded-lg">
        <div className="flex flex-wrap items-center gap-4">
          <div>
            <span className="block text-xs text-slate-400 mb-1">
              Sinkhole Target IP
            </span>
            <div className="flex items-center gap-1 p-1 bg-slate-950 border border-slate-800 rounded-md">
              <button
                type="button"
                onClick={() => setRedirectIp('0.0.0.0')}
                className={`px-2.5 py-1 text-xs font-mono rounded transition-colors whitespace-nowrap shrink-0 ${
                  redirectIp === '0.0.0.0'
                    ? 'bg-indigo-600 text-white font-medium'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                0.0.0.0 (Null Route)
              </button>
              <button
                type="button"
                onClick={() => setRedirectIp('127.0.0.1')}
                className={`px-2.5 py-1 text-xs font-mono rounded transition-colors whitespace-nowrap shrink-0 ${
                  redirectIp === '127.0.0.1'
                    ? 'bg-indigo-600 text-white font-medium'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                127.0.0.1 (Loopback)
              </button>
            </div>
          </div>

          <div className="flex items-center gap-4 pt-4">
            <label className="inline-flex items-center gap-2 text-xs text-slate-300 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={includeIpv6}
                onChange={(e) => setIncludeIpv6(e.target.checked)}
                className="rounded border-slate-700 bg-slate-950 text-indigo-500 focus:ring-indigo-500"
              />
              Include IPv6 (::0)
            </label>

            <label className="inline-flex items-center gap-2 text-xs text-slate-300 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={includeComments}
                onChange={(e) => setIncludeComments(e.target.checked)}
                className="rounded border-slate-700 bg-slate-950 text-indigo-500 focus:ring-indigo-500"
              />
              Include Audit Comments
            </label>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <div className="text-xs text-slate-400 font-mono tabular-nums">
            <span className="text-emerald-400 font-semibold">{activeDomainsCount}</span> /{' '}
            {uniqueDomains.length} domains ·{' '}
            <span className="text-indigo-300 font-semibold">{selectedFindingsCount}</span> /{' '}
            {totalFindingsCount} findings active
          </div>

          <button
            type="button"
            onClick={handleCopyHosts}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium text-slate-200 bg-slate-800 hover:bg-slate-700 rounded-md transition-colors whitespace-nowrap shrink-0"
          >
            {copiedHosts ? (
              <>
                <Check className="w-3.5 h-3.5 text-emerald-400" />
                Copied Hosts File
              </>
            ) : (
              <>
                <Copy className="w-3.5 h-3.5" />
                Copy Hosts Preview
              </>
            )}
          </button>

          <button
            type="button"
            onClick={handleDownloadHosts}
            className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-semibold text-slate-950 bg-emerald-400 hover:bg-emerald-300 rounded-md transition-colors whitespace-nowrap shrink-0"
          >
            <ArrowDownToLine className="w-3.5 h-3.5" />
            Download hosts File
          </button>
        </div>
      </div>

      {/* Main Split: Left Interactive Findings/Domains Toggler + Right Real-Time Hosts Preview & Firewall Generator */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left Column: Interactive Domain & Finding Selection List (5 cols) */}
        <div className="lg:col-span-5 bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
          <div className="p-4 border-b border-slate-800 space-y-3">
            <div className="flex items-center justify-between gap-2">
              <div>
                <h2 className="text-sm font-semibold text-slate-100">
                  Interactive Telemetry Findings ({uniqueDomains.length} Domains)
                </h2>
                <p className="text-xs text-slate-400 mt-0.5">
                  Toggle domains or individual binary offsets to update the hosts file in real time.
                </p>
              </div>
              <div className="flex items-center gap-1.5 shrink-0">
                <button
                  type="button"
                  onClick={() => onSetAllFindingsSelected(true)}
                  className="px-2 py-1 text-[11px] font-medium text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 rounded transition-colors"
                >
                  All
                </button>
                <button
                  type="button"
                  onClick={() => onSetAllFindingsSelected(false)}
                  className="px-2 py-1 text-[11px] font-medium text-slate-400 hover:text-white bg-slate-950 border border-slate-800 hover:bg-slate-800 rounded transition-colors"
                >
                  None
                </button>
              </div>
            </div>

            <input
              type="text"
              placeholder="Filter domains, vendors, or binaries..."
              value={filterQuery}
              onChange={(e) => setFilterQuery(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-md px-3 py-1.5 text-xs text-slate-100 focus:outline-none focus:border-indigo-500"
            />
          </div>

          <div className="divide-y divide-slate-800/70 max-h-[620px] overflow-y-auto">
            {filteredDomains.length === 0 ? (
              <div className="p-8 text-center text-sm text-slate-400">
                No telemetry domains match the current filter.
              </div>
            ) : (
              filteredDomains.map((item) => {
                const isExpanded = !!expandedDomains[item.domain];
                const allSelected = item.selectedOccurrences === item.occurrences;
                const partiallySelected =
                  item.selectedOccurrences > 0 && item.selectedOccurrences < item.occurrences;

                return (
                  <div key={item.domain} className="transition-colors">
                    <div
                      className={`p-3.5 flex items-start justify-between gap-3 ${
                        item.selected ? 'bg-slate-900 hover:bg-slate-800/40' : 'bg-slate-950/60 opacity-60 hover:opacity-90'
                      }`}
                    >
                      <div className="flex items-start gap-2.5 min-w-0">
                        <input
                          type="checkbox"
                          checked={item.selected}
                          ref={(el) => {
                            if (el) el.indeterminate = partiallySelected;
                          }}
                          onChange={(e) =>
                            onToggleDomainSelection(item.domain, e.target.checked)
                          }
                          aria-label={`Toggle domain ${item.domain}`}
                          className="mt-0.5 rounded border-slate-700 bg-slate-950 text-indigo-500 focus:ring-indigo-500 cursor-pointer"
                        />
                        <div className="min-w-0">
                          <div className="flex items-center gap-2">
                            <span
                              className={`font-mono text-xs font-semibold truncate ${
                                item.selected ? 'text-slate-100' : 'text-slate-500 line-through'
                              }`}
                            >
                              {item.domain}
                            </span>
                          </div>
                          <div className="mt-1 text-xs text-slate-400">
                            <span>{item.vendor}</span>
                            <span className="mx-1.5">·</span>
                            <span>{item.category}</span>
                          </div>
                          <div className="mt-1 text-[11px] text-slate-500 font-mono truncate">
                            Binaries: {item.files.join(', ')}
                          </div>
                        </div>
                      </div>

                      <div className="flex items-center gap-2 shrink-0">
                        <span
                          className={`text-xs font-mono tabular-nums ${
                            allSelected
                              ? 'text-emerald-400'
                              : partiallySelected
                              ? 'text-amber-300'
                              : 'text-slate-500'
                          }`}
                        >
                          {item.selectedOccurrences}/{item.occurrences}
                        </span>
                        <button
                          type="button"
                          onClick={() => toggleExpandDomain(item.domain)}
                          className="p-1 text-slate-400 hover:text-slate-200 rounded bg-slate-950 border border-slate-800"
                          title="Toggle individual binary offsets"
                        >
                          {isExpanded ? (
                            <ChevronDown className="w-3.5 h-3.5" />
                          ) : (
                            <ChevronRight className="w-3.5 h-3.5" />
                          )}
                        </button>
                      </div>
                    </div>

                    {/* Individual binary findings nested under domain */}
                    {isExpanded && (
                      <div className="bg-slate-950/90 border-t border-slate-800/80 px-4 py-2.5 space-y-2">
                        <div className="text-[11px] text-slate-400 font-medium">
                          Individual Binary Occurrences:
                        </div>
                        {item.findings.map((f) => (
                          <label
                            key={f.id}
                            className="flex items-start justify-between gap-2 py-1.5 px-2 rounded hover:bg-slate-900 cursor-pointer text-xs"
                          >
                            <div className="flex items-start gap-2 min-w-0">
                              <input
                                type="checkbox"
                                checked={f.selected}
                                onChange={() => onToggleFindingSelection(f.fileId, f.id)}
                                className="mt-0.5 rounded border-slate-700 bg-slate-900 text-indigo-500 focus:ring-indigo-500"
                              />
                              <div className="min-w-0 font-mono">
                                <div className="text-slate-200 text-[11px]">
                                  {f.fileName} ·{' '}
                                  <span className="text-indigo-300">
                                    0x{f.offset.toString(16).toUpperCase().padStart(8, '0')}
                                  </span>{' '}
                                  · <span className="text-slate-400">{f.encoding}</span>
                                </div>
                                <div className="text-[11px] text-slate-500 truncate">
                                  {f.rawString}
                                </div>
                              </div>
                            </div>
                            <span
                              className={`text-[11px] font-mono shrink-0 ${
                                f.selected ? 'text-emerald-400' : 'text-slate-500'
                              }`}
                            >
                              {f.selected ? 'Included' : 'Excluded'}
                            </span>
                          </label>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Right Column: Dynamic Live Hosts File Preview + Firewall & DNS Script Switcher (7 cols) */}
        <div className="lg:col-span-7 space-y-6">
          {/* Dedicated Real-Time Hosts File Preview Panel */}
          <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
            <div className="px-4 py-3 border-b border-slate-800 flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <Eye className="w-4 h-4 text-emerald-400" />
                <h2 className="text-sm font-semibold text-slate-100">
                  Live Generated <code className="font-mono text-emerald-300">hosts</code> File Preview
                </h2>
              </div>
              <div className="flex items-center gap-3 text-xs font-mono text-slate-400 tabular-nums">
                <span>
                  {activeDomainsCount} blocked {activeDomainsCount === 1 ? 'domain' : 'domains'}
                </span>
                <span>·</span>
                <span>{liveHostsLines.length} lines</span>
              </div>
            </div>

            {/* Syntax-Highlighted Real-Time Hosts Preview */}
            <div className="bg-slate-950 p-4 max-h-[340px] overflow-y-auto font-mono text-xs leading-relaxed">
              {liveHostsLines.map((line, idx) => {
                const isComment = line.trim().startsWith('#');
                const isIpv6 = line.trim().startsWith('::0');
                const isIpv4 =
                  line.trim().startsWith('0.0.0.0') || line.trim().startsWith('127.0.0.1');

                return (
                  <div
                    key={idx}
                    className="flex items-baseline gap-4 hover:bg-slate-900/60 px-1.5 py-0.5 rounded-xs"
                  >
                    <span className="w-7 text-right text-[11px] text-slate-600 select-none shrink-0 tabular-nums">
                      {idx + 1}
                    </span>
                    <span
                      className={`break-all ${
                        isComment
                          ? 'text-slate-500'
                          : isIpv4
                          ? 'text-emerald-300 font-medium'
                          : isIpv6
                          ? 'text-indigo-300'
                          : 'text-slate-300'
                      }`}
                    >
                      {line || ' '}
                    </span>
                  </div>
                );
              })}
            </div>

            <div className="px-4 py-2.5 bg-slate-900 border-t border-slate-800 flex flex-wrap items-center justify-between gap-2 text-xs text-slate-400">
              <span>
                Target paths: <code className="text-slate-300">/etc/hosts</code> (Linux/macOS) ·{' '}
                <code className="text-slate-300">C:\Windows\System32\drivers\etc\hosts</code>
              </span>
              <span className="text-emerald-400 font-mono">
                Real-Time Sync Active
              </span>
            </div>
          </div>

          {/* Multi-Platform Firewall & DNS Script Generator */}
          <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
            <div className="px-4 py-3 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <Terminal className="w-4 h-4 text-indigo-400" />
                <span className="text-sm font-semibold text-slate-100">
                  OS Firewall & DNS Sinkhole Script Generator
                </span>
              </div>

              <div className="flex flex-wrap items-center gap-1 p-1 bg-slate-950 border border-slate-800 rounded-md">
                <button
                  type="button"
                  onClick={() => setFormat('android_adb')}
                  className={`px-2.5 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 ${
                    format === 'android_adb'
                      ? 'bg-indigo-600 text-white'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  Android APK / ADB / AdAway
                </button>
                <button
                  type="button"
                  onClick={() => setFormat('powershell')}
                  className={`px-2.5 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 ${
                    format === 'powershell'
                      ? 'bg-indigo-600 text-white'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  Windows Firewall (.ps1)
                </button>
                <button
                  type="button"
                  onClick={() => setFormat('linux_dns')}
                  className={`px-2.5 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 ${
                    format === 'linux_dns'
                      ? 'bg-indigo-600 text-white'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  dnsmasq / Pi-hole
                </button>
                <button
                  type="button"
                  onClick={() => setFormat('littlesnitch')}
                  className={`px-2.5 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 ${
                    format === 'littlesnitch'
                      ? 'bg-indigo-600 text-white'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  Little Snitch (.lsrules)
                </button>
              </div>
            </div>

            <pre className="p-4 bg-slate-950 text-xs font-mono text-slate-200 overflow-x-auto max-h-[280px] leading-relaxed">
              {generatedFormatOutput}
            </pre>

            <div className="px-4 py-3 bg-slate-900 border-t border-slate-800 flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-2 text-xs text-slate-400">
                <ShieldAlert className="w-4 h-4 text-amber-400 shrink-0" />
                <span>
                  Automatically updates as findings are toggled ({activeDomainsCount} active domains).
                </span>
              </div>

              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={handleCopyFormatOutput}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-200 bg-slate-800 hover:bg-slate-700 rounded transition-colors whitespace-nowrap shrink-0"
                >
                  {copiedAux ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                      Copied Script
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5" />
                      Copy Script
                    </>
                  )}
                </button>
                <button
                  type="button"
                  onClick={handleDownloadFormat}
                  className="inline-flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-semibold text-white bg-indigo-600 hover:bg-indigo-500 rounded transition-colors whitespace-nowrap shrink-0"
                >
                  <FileText className="w-3.5 h-3.5" />
                  Download Script
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
