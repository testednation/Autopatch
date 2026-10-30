import React, { useMemo, useRef, useState } from 'react';
import {
  ArrowDownToLine,
  Check,
  Code2,
  FileCode,
  FileSpreadsheet,
  FolderOpen,
  LockOpen,
  PackageCheck,
  RotateCcw,
  Search,
  ShieldCheck,
  Trash2,
  Upload,
  Zap,
} from 'lucide-react';
import {
  PatchStrategy,
  ScannedBinaryFile,
  TelemetryFinding,
} from '../utils/binaryScanner';

interface ScannerReportViewProps {
  files: ScannedBinaryFile[];
  selectedFileId: string | 'ALL';
  onSelectFile: (id: string | 'ALL') => void;
  patchStrategy: PatchStrategy;
  onChangePatchStrategy: (strategy: PatchStrategy) => void;
  onFilesDropped: (fileList: { file: File; relativePath: string }[]) => void;
  onLoadSampleSuite: () => void;
  onClearAllFiles: () => void;
  onToggleFindingSelection: (fileId: string, findingId: string) => void;
  onToggleAllFindingsInView: (findings: TelemetryFinding[], selected: boolean) => void;
  onPatchAllFiles: () => void;
  onRestoreAllFiles: () => void;
  onDownloadPatchedFile: (file: ScannedBinaryFile) => void;
  onDownloadAllPatchedFiles: () => void;
  onRepackAndDownloadBundleZip: () => void;
  autoDownloadOnPatch: boolean;
  onToggleAutoDownloadOnPatch: (enabled: boolean) => void;
  onInspectFindingInHex: (finding: TelemetryFinding) => void;
  onNavigateToBlocker: () => void;
  isScanning: boolean;
}

type EncodingFilterMode =
  | 'All'
  | 'Obfuscated'
  | 'ASCII'
  | 'DEX-MUTF8'
  | 'UTF-16LE'
  | 'XOR-8'
  | 'Base64'
  | 'Reversed'
  | 'ROT13'
  | 'Hex-Encoded';

async function traverseFileTree(
  item: any,
  pathPrefix = ''
): Promise<{ file: File; relativePath: string }[]> {
  if (!item) return [];
  if (item.isFile) {
    return new Promise((resolve) => {
      item.file(
        (file: File) => {
          resolve([{ file, relativePath: pathPrefix + file.name }]);
        },
        () => resolve([])
      );
    });
  }
  if (item.isDirectory) {
    const dirReader = item.createReader();
    const entries: any[] = await new Promise((resolve) => {
      dirReader.readEntries(
        (results: any[]) => resolve(results || []),
        () => resolve([])
      );
    });
    const out: { file: File; relativePath: string }[] = [];
    for (const entry of entries) {
      const sub = await traverseFileTree(entry, `${pathPrefix}${item.name}/`);
      out.push(...sub);
    }
    return out;
  }
  return [];
}

export const ScannerReportView: React.FC<ScannerReportViewProps> = ({
  files,
  selectedFileId,
  onSelectFile,
  patchStrategy,
  onChangePatchStrategy,
  onFilesDropped,
  onLoadSampleSuite,
  onClearAllFiles,
  onToggleFindingSelection,
  onToggleAllFindingsInView,
  onPatchAllFiles,
  onRestoreAllFiles,
  onDownloadPatchedFile,
  onDownloadAllPatchedFiles,
  onRepackAndDownloadBundleZip,
  autoDownloadOnPatch,
  onToggleAutoDownloadOnPatch,
  onInspectFindingInHex,
  onNavigateToBlocker,
  isScanning,
}) => {
  const fileInputRef = useRef<HTMLInputElement>(null);
  const folderInputRef = useRef<HTMLInputElement>(null);

  const [isDragging, setIsDragging] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [categoryFilter, setCategoryFilter] = useState<string>('All');
  const [encodingFilter, setEncodingFilter] = useState<EncodingFilterMode>('All');

  const handleDrop = async (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);

    const items = e.dataTransfer.items;
    if (items && items.length > 0) {
      const collected: { file: File; relativePath: string }[] = [];
      for (let i = 0; i < items.length; i++) {
        const item = items[i];
        const entry = item.webkitGetAsEntry ? item.webkitGetAsEntry() : null;
        if (entry) {
          const sub = await traverseFileTree(entry);
          collected.push(...sub);
        } else {
          const f = item.getAsFile();
          if (f) collected.push({ file: f, relativePath: f.name });
        }
      }
      if (collected.length > 0) {
        onFilesDropped(collected);
        return;
      }
    }

    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      const list = Array.from(e.dataTransfer.files).map((f) => ({
        file: f,
        relativePath: (f as any).webkitRelativePath || f.name,
      }));
      onFilesDropped(list);
    }
  };

  const allFindings = useMemo(() => {
    if (selectedFileId === 'ALL') {
      return files.flatMap((f) => f.findings);
    }
    const target = files.find((f) => f.id === selectedFileId);
    return target ? target.findings : [];
  }, [files, selectedFileId]);

  const filteredFindings = useMemo(() => {
    return allFindings.filter((f) => {
      if (categoryFilter !== 'All' && f.category !== categoryFilter) return false;
      if (encodingFilter === 'Obfuscated') {
        if (
          f.encoding === 'ASCII' ||
          f.encoding === 'UTF-16LE' ||
          f.encoding === 'DEX-MUTF8'
        ) {
          return false;
        }
      } else if (encodingFilter !== 'All' && f.encoding !== encodingFilter) {
        return false;
      }
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        return (
          f.domain.toLowerCase().includes(q) ||
          f.rawString.toLowerCase().includes(q) ||
          f.vendor.toLowerCase().includes(q) ||
          f.fileName.toLowerCase().includes(q) ||
          f.sectionName.toLowerCase().includes(q) ||
          (f.obfuscationDetail && f.obfuscationDetail.toLowerCase().includes(q)) ||
          (f.encodedPreview && f.encodedPreview.toLowerCase().includes(q))
        );
      }
      return true;
    });
  }, [allFindings, categoryFilter, encodingFilter, searchQuery]);

  const [chartMode, setChartMode] = useState<'binary' | 'category'>('binary');
  const [hoveredSliceId, setHoveredSliceId] = useState<string | null>(null);

  // Metrics across entire workspace
  const metrics = useMemo(() => {
    const totalBytes = files.reduce((acc, f) => acc + f.size, 0);
    const totalHits = files.reduce((acc, f) => acc + f.findings.length, 0);
    const wideHits = files.reduce(
      (acc, f) => acc + f.findings.filter((x) => x.encoding === 'UTF-16LE').length,
      0
    );
    const asciiHits = files.reduce(
      (acc, f) => acc + f.findings.filter((x) => x.encoding === 'ASCII').length,
      0
    );
    const dexHits = files.reduce(
      (acc, f) => acc + f.findings.filter((x) => x.encoding === 'DEX-MUTF8').length,
      0
    );
    const obfuscatedHits = totalHits - asciiHits - wideHits - dexHits;
    const apkCount = files.filter((f) => f.isAPK || f.isDEX).length;
    const packedBinariesCount = files.filter((f) => f.packerDetected !== null).length;
    const uniqueDomains = new Set(files.flatMap((f) => f.findings.map((x) => x.domain))).size;
    const patchedHits = files.reduce(
      (acc, f) => acc + f.findings.filter((x) => x.patched).length,
      0
    );
    const selectedHits = files.reduce(
      (acc, f) => acc + f.findings.filter((x) => x.selected).length,
      0
    );
    const modifiedFilesCount = files.filter((f) => f.isModified).length;

    return {
      totalBytes,
      totalHits,
      wideHits,
      asciiHits,
      dexHits,
      obfuscatedHits,
      apkCount,
      packedBinariesCount,
      uniqueDomains,
      patchedHits,
      selectedHits,
      modifiedFilesCount,
    };
  }, [files]);

  // Donut Chart Distribution Data (by Scanned Binary or by Category)
  const donutSlices = useMemo(() => {
    const palette = [
      { stroke: '#6366f1', bg: 'bg-indigo-500', text: 'text-indigo-300' },
      { stroke: '#f43f5e', bg: 'bg-rose-500', text: 'text-rose-300' },
      { stroke: '#10b981', bg: 'bg-emerald-500', text: 'text-emerald-300' },
      { stroke: '#f59e0b', bg: 'bg-amber-500', text: 'text-amber-300' },
      { stroke: '#06b6d4', bg: 'bg-cyan-500', text: 'text-cyan-300' },
      { stroke: '#a855f7', bg: 'bg-purple-500', text: 'text-purple-300' },
    ];

    if (chartMode === 'binary') {
      const total = files.reduce((acc, f) => acc + f.findings.length, 0);
      let cumulativeRatio = 0;

      return files
        .filter((f) => f.findings.length > 0)
        .map((file, idx) => {
          const count = file.findings.length;
          const uniqueDomainsCount = new Set(file.findings.map((x) => x.domain)).size;
          const asciiCount = file.findings.filter(
            (x) => x.encoding === 'ASCII' || x.encoding === 'DEX-MUTF8'
          ).length;
          const wideCount = file.findings.filter((x) => x.encoding === 'UTF-16LE').length;
          const obfCount = count - asciiCount - wideCount;
          const ratio = total > 0 ? count / total : 0;
          const startRatio = cumulativeRatio;
          cumulativeRatio += ratio;
          const color = palette[idx % palette.length];

          return {
            id: file.id,
            label: file.name,
            sublabel: `${file.architecture} · Entropy ${file.overallEntropy.toFixed(2)} b/B${
              file.packerDetected ? ` · ${file.packerDetected}` : ''
            }`,
            count,
            uniqueDomainsCount,
            asciiCount,
            wideCount,
            obfCount,
            percentage: total > 0 ? (count / total) * 100 : 0,
            ratio,
            startRatio,
            color,
          };
        });
    } else {
      const all = files.flatMap((f) => f.findings);
      const total = all.length;
      const byCat = new Map<
        string,
        { count: number; domains: Set<string>; ascii: number; wide: number; obf: number }
      >();

      for (const hit of all) {
        const cur = byCat.get(hit.category) || {
          count: 0,
          domains: new Set<string>(),
          ascii: 0,
          wide: 0,
          obf: 0,
        };
        cur.count += 1;
        cur.domains.add(hit.domain);
        if (hit.encoding === 'ASCII' || hit.encoding === 'DEX-MUTF8') cur.ascii += 1;
        else if (hit.encoding === 'UTF-16LE') cur.wide += 1;
        else cur.obf += 1;
        byCat.set(hit.category, cur);
      }

      let cumulativeRatio = 0;
      return Array.from(byCat.entries())
        .sort((a, b) => b[1].count - a[1].count)
        .map(([catName, stat], idx) => {
          const ratio = total > 0 ? stat.count / total : 0;
          const startRatio = cumulativeRatio;
          cumulativeRatio += ratio;
          const color = palette[idx % palette.length];

          return {
            id: catName,
            label: catName,
            sublabel: `${stat.domains.size} unique domains`,
            count: stat.count,
            uniqueDomainsCount: stat.domains.size,
            asciiCount: stat.ascii,
            wideCount: stat.wide,
            obfCount: stat.obf,
            percentage: total > 0 ? (stat.count / total) * 100 : 0,
            ratio,
            startRatio,
            color,
          };
        });
    }
  }, [files, chartMode]);

  const activeDonutSlice = useMemo(() => {
    if (hoveredSliceId) {
      const hovered = donutSlices.find((s) => s.id === hoveredSliceId);
      if (hovered) return hovered;
    }
    if (chartMode === 'binary' && selectedFileId !== 'ALL') {
      return donutSlices.find((s) => s.id === selectedFileId) || null;
    }
    if (chartMode === 'category' && categoryFilter !== 'All') {
      return donutSlices.find((s) => s.id === categoryFilter) || null;
    }
    return null;
  }, [donutSlices, hoveredSliceId, chartMode, selectedFileId, categoryFilter]);

  const handleExportReportMarkdown = () => {
    const lines: string[] = [
      '# NullRoute Offline Binary & Android APK Telemetry Audit Report',
      `Generated: ${new Date().toISOString()}`,
      `Scanned Files: ${files.length}`,
      `Total Telemetry Endpoints Found: ${metrics.totalHits} (${metrics.asciiHits} ASCII, ${metrics.dexHits} DEX-MUTF8, ${metrics.wideHits} UTF-16LE, ${metrics.obfuscatedHits} Obfuscated)`,
      `Unique Domains: ${metrics.uniqueDomains}`,
      '',
      '## Scanned Binaries, APKs, Entropy & Checksums',
      '| File | Architecture | Entropy (b/B) | Packer / Protector | Size (Bytes) | Original SHA-256 | Working SHA-256 | Status |',
      '| :--- | :--- | ---: | :--- | ---: | :--- | :--- | :--- |',
    ];

    for (const f of files) {
      lines.push(
        `| ${f.relativePath} | ${f.architecture} | ${f.overallEntropy.toFixed(2)} | ${f.packerDetected || 'None'} | ${f.size} | \`${f.originalSha256.slice(0, 16)}...\` | \`${f.workingSha256.slice(0, 16)}...\` | ${f.isModified ? 'Patched' : 'Original'} |`
      );
    }

    lines.push('');
    lines.push('## Detected Telemetry Endpoints (PE, DEX, Native .so & Deobfuscated)');
    lines.push(
      '| Binary / APK | Offset | Section / Entry | Encoding / Cipher | Bytes | Domain | Vendor | Category | Deobfuscated URL | Status |'
    );
    lines.push('| :--- | :--- | :--- | :--- | ---: | :--- | :--- | :--- | :--- | :--- |');

    for (const f of files) {
      for (const hit of f.findings) {
        const encLabel = hit.obfuscationDetail
          ? `${hit.encoding} (${hit.obfuscationDetail})`
          : hit.encoding;
        lines.push(
          `| ${f.name} | \`0x${hit.offset.toString(16).toUpperCase().padStart(8, '0')}\` | \`${hit.sectionName}\` | ${encLabel} | ${hit.byteLength} | \`${hit.domain}\` | ${hit.vendor} | ${hit.category} | \`${hit.rawString}\` | ${hit.patched ? 'Patched' : 'Unpatched'} |`
        );
      }
    }

    const blob = new Blob([lines.join('\n')], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'NullRoute-Telemetry-Audit-Report.md';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const categories = [
    'All',
    'Mobile SDK & MMP',
    'Crash & Error Reporting',
    'Behavioral Analytics',
    'Vendor Diagnostics',
    'Ad-Tech & Attribution',
    'Heuristic Subdomain',
    'Custom Rule',
  ];

  const encodingModes: EncodingFilterMode[] = [
    'All',
    'DEX-MUTF8',
    'Obfuscated',
    'ASCII',
    'UTF-16LE',
    'XOR-8',
    'Base64',
    'Reversed',
    'ROT13',
    'Hex-Encoded',
  ];

  const allFilteredSelected =
    filteredFindings.length > 0 && filteredFindings.every((f) => f.selected);

  return (
    <div className="space-y-6">
      {/* Hidden File & Directory Inputs */}
      <input
        ref={fileInputRef}
        type="file"
        multiple
        onChange={(e) => {
          if (e.target.files && e.target.files.length > 0) {
            const list = Array.from(e.target.files).map((f) => ({
              file: f,
              relativePath: f.name,
            }));
            onFilesDropped(list);
            e.target.value = '';
          }
        }}
        className="hidden"
      />
      <input
        ref={folderInputRef}
        type="file"
        multiple
        {...({ webkitdirectory: '', directory: '' } as any)}
        onChange={(e) => {
          if (e.target.files && e.target.files.length > 0) {
            const list = Array.from(e.target.files).map((f) => ({
              file: f,
              relativePath: (f as any).webkitRelativePath || f.name,
            }));
            onFilesDropped(list);
            e.target.value = '';
          }
        }}
        className="hidden"
      />

      {/* Offline Dropzone & Quick Loader Banner */}
      <div
        onDragOver={(e) => {
          e.preventDefault();
          setIsDragging(true);
        }}
        onDragLeave={() => setIsDragging(false)}
        onDrop={handleDrop}
        className={`border rounded-lg p-6 transition-colors ${
          isDragging
            ? 'border-indigo-500 bg-indigo-950/30'
            : 'border-slate-800 bg-slate-900/70'
        }`}
      >
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-6">
          <div className="space-y-1.5 max-w-2xl">
            <h1 className="text-xl font-bold tracking-tight text-slate-100">
              Offline Executable, Android APK & Obfuscated Binary Patcher
            </h1>
            <p className="text-sm text-slate-400 leading-relaxed">
              Drop any Android <code className="text-emerald-300">.apk</code>,{' '}
              <code className="text-emerald-300">classes.dex</code>, Windows{' '}
              <code className="text-slate-200">.exe</code> /{' '}
              <code className="text-slate-200">.dll</code>, Linux/NDK{' '}
              <code className="text-slate-200">.so</code>, or application folder. Unpacks APK
              containers in memory, inspects Dalvik <code className="text-slate-300">DEX-MUTF8</code>{' '}
              string pools, <code className="text-slate-300">AndroidManifest.xml</code>, and
              obfuscated strings (<code className="text-slate-300">XOR-8</code>,{' '}
              <code className="text-slate-300">Base64</code>,{' '}
              <code className="text-slate-300">Reversed</code>,{' '}
              <code className="text-slate-300">ROT13</code>), and patches in-place while recalculating
              DEX Adler-32/SHA-1 & ZIP CRC-32 checksums.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2.5 shrink-0">
            <button
              type="button"
              onClick={() => fileInputRef.current?.click()}
              className="inline-flex items-center gap-2 px-3.5 py-2 text-xs font-semibold text-white bg-indigo-600 hover:bg-indigo-500 rounded-md transition-colors whitespace-nowrap shrink-0"
            >
              <Upload className="w-3.5 h-3.5" />
              Select Binary / APK (.apk, .dex, .exe)
            </button>
            <button
              type="button"
              onClick={() => folderInputRef.current?.click()}
              className="inline-flex items-center gap-2 px-3.5 py-2 text-xs font-semibold text-slate-100 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-md transition-colors whitespace-nowrap shrink-0"
            >
              <FolderOpen className="w-3.5 h-3.5" />
              Scan Entire Folder
            </button>
            <button
              type="button"
              onClick={onLoadSampleSuite}
              className="inline-flex items-center gap-2 px-3.5 py-2 text-xs font-medium text-slate-300 bg-slate-950 hover:bg-slate-800 border border-slate-800 rounded-md transition-colors whitespace-nowrap shrink-0"
            >
              <FileCode className="w-3.5 h-3.5 text-indigo-400" />
              Reload Sample APK & PE Suite
            </button>
          </div>
        </div>
      </div>

      {/* 4-Column Quantitative Audit Strip */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
          <div className="text-xs text-slate-400">Scanned Binaries & APKs</div>
          <div className="mt-1 text-2xl font-bold text-slate-100 font-mono tabular-nums">
            {files.length}
          </div>
          <div className="mt-1 text-xs text-slate-400 font-mono tabular-nums">
            {(metrics.totalBytes / 1024).toFixed(1)} KB · {metrics.apkCount} Android APK/DEX
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
          <div className="text-xs text-slate-400">Telemetry Strings Located</div>
          <div className="mt-1 text-2xl font-bold text-rose-400 font-mono tabular-nums">
            {metrics.totalHits}
          </div>
          <div className="mt-1 text-xs text-slate-400 font-mono tabular-nums">
            {metrics.dexHits} DEX · {metrics.asciiHits + metrics.wideHits} PE/ELF ·{' '}
            <span className="text-amber-300">{metrics.obfuscatedHits} Obf</span>
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
          <div className="text-xs text-slate-400">Unique Tracking Domains</div>
          <div className="mt-1 text-2xl font-bold text-amber-300 font-mono tabular-nums">
            {metrics.uniqueDomains}
          </div>
          <div className="mt-1 text-xs text-slate-400">
            <button
              type="button"
              onClick={onNavigateToBlocker}
              className="text-indigo-400 hover:text-indigo-300 underline underline-offset-2"
            >
              Generate Hosts & Firewall Blocklist →
            </button>
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
          <div className="text-xs text-slate-400">Hex Patch Status</div>
          <div className="mt-1 text-2xl font-bold text-emerald-400 font-mono tabular-nums">
            {metrics.patchedHits} / {metrics.selectedHits}
          </div>
          <div className="mt-1 text-xs text-slate-400 font-mono tabular-nums">
            {metrics.modifiedFilesCount} of {files.length} binaries modified in memory
          </div>
        </div>
      </div>

      {/* Telemetry Distribution Donut Chart Visualization */}
      {files.length > 0 && metrics.totalHits > 0 && (
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-5">
          <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-slate-800">
            <div>
              <h2 className="text-sm font-semibold text-slate-100">
                Telemetry Domain Distribution Across Scanned Binaries
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Click any segment or binary row to isolate its plaintext and deobfuscated telemetry
                occurrences below.
              </p>
            </div>

            <div className="flex items-center gap-2">
              {(selectedFileId !== 'ALL' || categoryFilter !== 'All') && (
                <button
                  type="button"
                  onClick={() => {
                    onSelectFile('ALL');
                    setCategoryFilter('All');
                  }}
                  className="px-2.5 py-1 text-xs font-medium text-indigo-300 hover:text-white bg-indigo-950/60 border border-indigo-800/60 rounded transition-colors whitespace-nowrap shrink-0"
                >
                  Reset Filter
                </button>
              )}
              <div className="flex items-center gap-1 p-1 bg-slate-950 border border-slate-800 rounded-md">
                <button
                  type="button"
                  onClick={() => setChartMode('binary')}
                  className={`px-3 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 ${
                    chartMode === 'binary'
                      ? 'bg-indigo-600 text-white'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  By Binary ({files.length})
                </button>
                <button
                  type="button"
                  onClick={() => setChartMode('category')}
                  className={`px-3 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 ${
                    chartMode === 'category'
                      ? 'bg-indigo-600 text-white'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  By Category
                </button>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 pt-5 items-center">
            {/* SVG Donut Chart (4 cols) */}
            <div className="lg:col-span-4 flex flex-col items-center justify-center">
              <div className="relative w-52 h-52 flex items-center justify-center">
                <svg
                  viewBox="0 0 200 200"
                  className="w-full h-full -rotate-90 overflow-visible"
                  role="img"
                  aria-label="Donut chart of telemetry domain distribution across scanned binaries"
                >
                  <circle
                    cx="100"
                    cy="100"
                    r="74"
                    fill="transparent"
                    stroke="#1e293b"
                    strokeWidth="22"
                  />

                  {donutSlices.map((slice) => {
                    const radius = 74;
                    const circumference = 2 * Math.PI * radius;
                    const gap = donutSlices.length > 1 ? 3 : 0;
                    const dashLength = Math.max(0, slice.ratio * circumference - gap);
                    const dashOffset = -slice.startRatio * circumference;
                    const isFocused = activeDonutSlice?.id === slice.id;

                    return (
                      <circle
                        key={slice.id}
                        cx="100"
                        cy="100"
                        r={radius}
                        fill="transparent"
                        stroke={slice.color.stroke}
                        strokeWidth={isFocused ? 27 : 22}
                        strokeDasharray={`${dashLength} ${circumference}`}
                        strokeDashoffset={dashOffset}
                        className="cursor-pointer transition-opacity duration-150"
                        style={{
                          opacity: activeDonutSlice && !isFocused ? 0.45 : 1,
                        }}
                        onMouseEnter={() => setHoveredSliceId(slice.id)}
                        onMouseLeave={() => setHoveredSliceId(null)}
                        onClick={() => {
                          if (chartMode === 'binary') {
                            onSelectFile(selectedFileId === slice.id ? 'ALL' : slice.id);
                          } else {
                            setCategoryFilter(
                              categoryFilter === slice.id ? 'All' : slice.id
                            );
                          }
                        }}
                      />
                    );
                  })}
                </svg>

                {/* Donut Center Readout */}
                <div className="absolute inset-0 flex flex-col items-center justify-center text-center pointer-events-none px-6">
                  {activeDonutSlice ? (
                    <>
                      <div className="text-2xl font-bold font-mono text-slate-100 tabular-nums">
                        {activeDonutSlice.count}
                      </div>
                      <div className="text-[11px] font-mono text-indigo-300 tabular-nums">
                        {activeDonutSlice.percentage.toFixed(1)}% of hits
                      </div>
                      <div className="mt-1 text-[11px] text-slate-300 font-medium truncate max-w-[125px]">
                        {activeDonutSlice.label}
                      </div>
                    </>
                  ) : (
                    <>
                      <div className="text-2xl font-bold font-mono text-slate-100 tabular-nums">
                        {metrics.totalHits}
                      </div>
                      <div className="text-[11px] text-slate-400">
                        Total Endpoints
                      </div>
                      <div className="mt-0.5 text-[11px] font-mono text-amber-300 tabular-nums">
                        {metrics.obfuscatedHits} obfuscated
                      </div>
                    </>
                  )}
                </div>
              </div>
            </div>

            {/* Interactive Distribution Breakdown Table (8 cols) */}
            <div className="lg:col-span-8">
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="border-b border-slate-800 text-[11px] font-medium text-slate-400">
                      <th className="py-2 px-3">
                        {chartMode === 'binary' ? 'Scanned Binary' : 'Telemetry Category'}
                      </th>
                      <th className="py-2 px-3 text-right">Unique Domains</th>
                      <th className="py-2 px-3 text-right">Encoding & Obfuscation Split</th>
                      <th className="py-2 px-3 text-right">Endpoints</th>
                      <th className="py-2 px-3 w-36">Distribution Share</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/70 text-xs">
                    {donutSlices.map((slice) => {
                      const isSelected =
                        (chartMode === 'binary' && selectedFileId === slice.id) ||
                        (chartMode === 'category' && categoryFilter === slice.id);

                      return (
                        <tr
                          key={slice.id}
                          onMouseEnter={() => setHoveredSliceId(slice.id)}
                          onMouseLeave={() => setHoveredSliceId(null)}
                          onClick={() => {
                            if (chartMode === 'binary') {
                              onSelectFile(selectedFileId === slice.id ? 'ALL' : slice.id);
                            } else {
                              setCategoryFilter(
                                categoryFilter === slice.id ? 'All' : slice.id
                              );
                            }
                          }}
                          className={`cursor-pointer transition-colors ${
                            isSelected
                              ? 'bg-indigo-950/50'
                              : hoveredSliceId === slice.id
                              ? 'bg-slate-800/60'
                              : 'hover:bg-slate-800/40'
                          }`}
                        >
                          <td className="py-2.5 px-3">
                            <div className="flex items-center gap-2.5">
                              <span
                                className={`w-2.5 h-2.5 rounded-xs shrink-0 ${slice.color.bg}`}
                              />
                              <div className="min-w-0">
                                <div className="font-mono font-semibold text-slate-100 truncate">
                                  {slice.label}
                                </div>
                                <div className="text-[11px] text-slate-400">
                                  {slice.sublabel}
                                </div>
                              </div>
                            </div>
                          </td>
                          <td className="py-2.5 px-3 text-right font-mono text-amber-300 tabular-nums">
                            {slice.uniqueDomainsCount}
                          </td>
                          <td className="py-2.5 px-3 text-right font-mono text-[11px] text-slate-400 tabular-nums whitespace-nowrap">
                            {slice.asciiCount} ASCII · {slice.wideCount} Wide ·{' '}
                            <span
                              className={
                                slice.obfCount > 0 ? 'text-amber-300 font-medium' : 'text-slate-500'
                              }
                            >
                              {slice.obfCount} Obf
                            </span>
                          </td>
                          <td className="py-2.5 px-3 text-right font-mono font-semibold text-slate-100 tabular-nums">
                            {slice.count}
                          </td>
                          <td className="py-2.5 px-3">
                            <div className="flex items-center gap-2">
                              <div className="flex-1 h-1.5 bg-slate-950 rounded-full overflow-hidden">
                                <div
                                  className={`h-full ${slice.color.bg}`}
                                  style={{ width: `${Math.max(4, slice.percentage)}%` }}
                                />
                              </div>
                              <span className="font-mono text-[11px] text-slate-300 tabular-nums w-11 text-right">
                                {slice.percentage.toFixed(1)}%
                              </span>
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Action & Batch Patching Bar */}
      <div className="flex flex-wrap items-center justify-between gap-4 p-4 bg-slate-900 border border-slate-800 rounded-lg">
        <div className="flex flex-wrap items-center gap-4">
          <div className="flex flex-wrap items-center gap-3">
            <span className="text-xs font-medium text-slate-300">Hex Replacement Mode:</span>
            <div className="flex items-center gap-1 p-1 bg-slate-950 border border-slate-800 rounded-md">
              <button
                type="button"
                onClick={() => onChangePatchStrategy('loopback')}
                className={`px-3 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 ${
                  patchStrategy === 'loopback'
                    ? 'bg-indigo-600 text-white'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Loopback (0.0.0.0 + Cipher-Aware Pad)
              </button>
              <button
                type="button"
                onClick={() => onChangePatchStrategy('nxdomain')}
                className={`px-3 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 ${
                  patchStrategy === 'nxdomain'
                    ? 'bg-indigo-600 text-white'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Host Sinkhole (In-Place)
              </button>
              <button
                type="button"
                onClick={() => onChangePatchStrategy('null_wipe')}
                className={`px-3 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 ${
                  patchStrategy === 'null_wipe'
                    ? 'bg-indigo-600 text-white'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Full Null / Key Wipe
              </button>
            </div>
          </div>

          <label className="inline-flex items-center gap-2 text-xs text-slate-300 cursor-pointer select-none px-2.5 py-1.5 bg-slate-950 border border-slate-800 rounded-md">
            <input
              type="checkbox"
              checked={autoDownloadOnPatch}
              onChange={(e) => onToggleAutoDownloadOnPatch(e.target.checked)}
              className="rounded border-slate-700 bg-slate-900 text-indigo-500 focus:ring-indigo-500"
            />
            <span>Auto-download repacked file on patch</span>
          </label>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {metrics.modifiedFilesCount > 0 && (
            <button
              type="button"
              onClick={onRestoreAllFiles}
              className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 rounded-md transition-colors whitespace-nowrap shrink-0"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              Revert All Binaries
            </button>
          )}

          <button
            type="button"
            onClick={handleExportReportMarkdown}
            disabled={files.length === 0}
            className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-slate-200 bg-slate-800 hover:bg-slate-700 disabled:opacity-40 rounded-md transition-colors whitespace-nowrap shrink-0"
          >
            <FileSpreadsheet className="w-3.5 h-3.5" />
            Export Audit Report (.md)
          </button>

          <button
            type="button"
            onClick={onPatchAllFiles}
            disabled={metrics.selectedHits === 0}
            className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-semibold text-white bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 rounded-md transition-colors whitespace-nowrap shrink-0"
          >
            <Zap className="w-3.5 h-3.5" />
            Patch & Auto-Repack Selected ({metrics.selectedHits})
          </button>

          <button
            type="button"
            onClick={onRepackAndDownloadBundleZip}
            disabled={files.length === 0}
            className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-semibold text-slate-950 bg-emerald-400 hover:bg-emerald-300 disabled:opacity-40 rounded-md transition-colors whitespace-nowrap shrink-0"
          >
            <PackageCheck className="w-3.5 h-3.5" />
            Repack & Download Bundle (.zip)
          </button>

          {metrics.modifiedFilesCount > 0 && (
            <button
              type="button"
              onClick={onDownloadAllPatchedFiles}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium text-emerald-300 bg-emerald-950/60 hover:bg-emerald-900/60 border border-emerald-800/60 rounded-md transition-colors whitespace-nowrap shrink-0"
            >
              <ArrowDownToLine className="w-3.5 h-3.5" />
              Save Individual Files ({metrics.modifiedFilesCount})
            </button>
          )}
        </div>
      </div>

      {/* Main Split: Left Scanned Files List + Right Findings Data Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left Sidebar: Scanned Binaries in Folder/Session (3 cols) */}
        <div className="lg:col-span-3 bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-slate-100">
              Loaded Binaries ({files.length})
            </h2>
            {files.length > 0 && (
              <button
                type="button"
                onClick={onClearAllFiles}
                className="text-xs text-slate-400 hover:text-rose-400 inline-flex items-center gap-1"
                title="Clear workspace"
              >
                <Trash2 className="w-3 h-3" />
                Clear
              </button>
            )}
          </div>

          <div className="divide-y divide-slate-800/70 max-h-[600px] overflow-y-auto">
            <button
              type="button"
              onClick={() => onSelectFile('ALL')}
              className={`w-full text-left p-3.5 transition-colors flex items-center justify-between ${
                selectedFileId === 'ALL'
                  ? 'bg-indigo-950/50 text-white'
                  : 'text-slate-300 hover:bg-slate-800/50'
              }`}
            >
              <div>
                <div className="text-xs font-semibold">All Scanned Files</div>
                <div className="text-[11px] text-slate-400 mt-0.5">
                  Combined folder & deobfuscation report
                </div>
              </div>
              <span className="text-xs font-mono text-indigo-300 tabular-nums">
                {metrics.totalHits} hits
              </span>
            </button>

            {files.map((file) => {
              const isSelected = selectedFileId === file.id;
              return (
                <div
                  key={file.id}
                  onClick={() => onSelectFile(file.id)}
                  className={`p-3.5 cursor-pointer transition-colors ${
                    isSelected ? 'bg-indigo-950/50' : 'hover:bg-slate-800/50'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-mono font-semibold text-slate-100 truncate">
                      {file.name}
                    </span>
                    <span className="text-xs font-mono text-rose-400 tabular-nums shrink-0">
                      {file.findings.length}
                    </span>
                  </div>

                  <div className="mt-1 text-[11px] text-slate-400 font-mono truncate">
                    {file.relativePath}
                  </div>

                  <div className="mt-1.5 text-[11px] text-slate-400 font-mono flex items-center justify-between">
                    <span>Entropy: {file.overallEntropy.toFixed(2)} b/B</span>
                    {file.obfuscatedHitsCount > 0 && (
                      <span className="text-amber-300">
                        {file.obfuscatedHitsCount} obfuscated
                      </span>
                    )}
                  </div>

                  {file.packerDetected && (
                    <div className="mt-1 text-[11px] text-amber-300/90 truncate">
                      Protector: {file.packerDetected}
                    </div>
                  )}

                  {file.isModified && file.repackInfo && (
                    <div className="mt-1 text-[11px] text-emerald-400 font-mono truncate">
                      Repacked: {file.repackInfo.summary}
                    </div>
                  )}

                  <div className="mt-2 flex items-center justify-between text-[11px] text-slate-400">
                    <span>
                      {file.architecture} · {(file.size / 1024).toFixed(1)} KB
                    </span>
                    {file.isModified ? (
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          onDownloadPatchedFile(file);
                        }}
                        className="text-emerald-400 hover:text-emerald-300 font-medium inline-flex items-center gap-1"
                      >
                        <ArrowDownToLine className="w-3 h-3" /> Save Repacked
                      </button>
                    ) : (
                      <span className="text-slate-500">Unmodified</span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right: Detailed Telemetry Findings Table (9 cols) */}
        <div className="lg:col-span-9 bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
          {/* Table Filter Bar */}
          <div className="p-4 border-b border-slate-800 space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-3">
                <h2 className="text-sm font-semibold text-slate-100">
                  Telemetry & Deobfuscated Domain Report ({filteredFindings.length})
                </h2>
                {isScanning && (
                  <span className="text-xs text-indigo-400 font-mono">
                    Scanning & deobfuscating binary buffers...
                  </span>
                )}
              </div>

              <div className="relative w-64">
                <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  placeholder="Filter domain, XOR key, Base64..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-md pl-8 pr-3 py-1.5 text-xs text-slate-100 focus:outline-none focus:border-indigo-500"
                />
              </div>
            </div>

            {/* Encoding & Deobfuscation Mode Filter */}
            <div className="flex flex-wrap items-center gap-1 p-1 bg-slate-950 border border-slate-800 rounded-md">
              {encodingModes.map((enc) => (
                <button
                  key={enc}
                  type="button"
                  onClick={() => setEncodingFilter(enc)}
                  className={`px-2.5 py-1 text-xs font-mono rounded transition-colors whitespace-nowrap shrink-0 ${
                    encodingFilter === enc
                      ? 'bg-indigo-600 text-white font-medium'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {enc}
                </button>
              ))}
            </div>

            {/* Category Segmented Filter */}
            <div className="flex flex-wrap items-center gap-1 p-1 bg-slate-950 border border-slate-800 rounded-md">
              {categories.map((cat) => (
                <button
                  key={cat}
                  type="button"
                  onClick={() => setCategoryFilter(cat)}
                  className={`px-2.5 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 ${
                    categoryFilter === cat
                      ? 'bg-slate-800 text-white'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {cat}
                </button>
              ))}
            </div>
          </div>

          {/* Data Grid */}
          {filteredFindings.length === 0 ? (
            <div className="p-12 text-center space-y-2">
              <ShieldCheck className="w-8 h-8 text-emerald-400 mx-auto" />
              <div className="text-sm font-medium text-slate-200">
                No matching telemetry domains in current view
              </div>
              <p className="text-xs text-slate-400 max-w-md mx-auto">
                Drop an executable or folder above, or clear active search filters to inspect
                detected plaintext and obfuscated endpoints.
              </p>
            </div>
          ) : (
            <div className="overflow-x-auto max-h-[560px] overflow-y-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-slate-800 bg-slate-950/70 text-[11px] font-medium text-slate-400">
                    <th className="py-2.5 px-3 w-8">
                      <input
                        type="checkbox"
                        checked={allFilteredSelected}
                        onChange={(e) =>
                          onToggleAllFindingsInView(filteredFindings, e.target.checked)
                        }
                        aria-label="Select all visible findings"
                        className="rounded border-slate-700 bg-slate-950 text-indigo-500 focus:ring-indigo-500"
                      />
                    </th>
                    <th className="py-2.5 px-3">Binary & Offset</th>
                    <th className="py-2.5 px-3">Detected Domain & Deobfuscated String</th>
                    <th className="py-2.5 px-3">Vendor & Category</th>
                    <th className="py-2.5 px-3">Encoding / Obfuscation</th>
                    <th className="py-2.5 px-3 text-right">Hex Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/70 text-xs">
                  {filteredFindings.map((hit) => {
                    const isObfuscated =
                      hit.encoding !== 'ASCII' && hit.encoding !== 'UTF-16LE';

                    return (
                      <tr key={hit.id} className="hover:bg-slate-800/40 transition-colors">
                        <td className="py-3 px-3 align-top">
                          <input
                            type="checkbox"
                            checked={hit.selected}
                            onChange={() => onToggleFindingSelection(hit.fileId, hit.id)}
                            aria-label={`Select ${hit.domain}`}
                            className="rounded border-slate-700 bg-slate-950 text-indigo-500 focus:ring-indigo-500 mt-0.5"
                          />
                        </td>
                        <td className="py-3 px-3 align-top whitespace-nowrap font-mono">
                          <div className="text-slate-200 font-medium">{hit.fileName}</div>
                          <div className="text-indigo-300 text-[11px] tabular-nums mt-0.5">
                            0x{hit.offset.toString(16).toUpperCase().padStart(8, '0')} ·{' '}
                            <span className="text-slate-400">{hit.sectionName}</span>
                          </div>
                        </td>
                        <td className="py-3 px-3 align-top max-w-xs">
                          <div className="font-mono font-semibold text-rose-300">
                            {hit.domain}
                          </div>
                          <div
                            className="font-mono text-[11px] text-slate-300 truncate mt-0.5"
                            title={hit.rawString}
                          >
                            {hit.rawString}
                          </div>
                          {hit.encodedPreview && (
                            <div
                              className="font-mono text-[11px] text-amber-300/80 truncate mt-0.5"
                              title={hit.encodedPreview}
                            >
                              Raw in binary: {hit.encodedPreview}
                            </div>
                          )}
                        </td>
                        <td className="py-3 px-3 align-top">
                          <div className="text-slate-200 font-medium">{hit.vendor}</div>
                          <div className="text-[11px] text-slate-400 mt-0.5">
                            <span>{hit.category}</span>
                            <span className="mx-1.5">·</span>
                            <span
                              className={
                                hit.severity === 'High'
                                  ? 'text-rose-400'
                                  : hit.severity === 'Medium'
                                  ? 'text-amber-300'
                                  : 'text-slate-400'
                              }
                            >
                              {hit.severity}
                            </span>
                          </div>
                        </td>
                        <td className="py-3 px-3 align-top whitespace-nowrap font-mono text-[11px] tabular-nums">
                          <div
                            className={
                              isObfuscated
                                ? 'text-amber-300 font-semibold inline-flex items-center gap-1'
                                : 'text-slate-300'
                            }
                          >
                            {isObfuscated && <LockOpen className="w-3 h-3 shrink-0" />}
                            {hit.encoding}
                          </div>
                          <div className="text-slate-500 mt-0.5">
                            {hit.obfuscationDetail
                              ? `${hit.obfuscationDetail} · ${hit.byteLength}B`
                              : `${hit.byteLength} bytes`}
                          </div>
                        </td>
                        <td className="py-3 px-3 align-top text-right whitespace-nowrap">
                          <div className="flex items-center justify-end gap-2">
                            {hit.patched && (
                              <span className="text-emerald-400 font-medium inline-flex items-center gap-1 text-[11px]">
                                <Check className="w-3 h-3" /> Patched
                              </span>
                            )}
                            <button
                              type="button"
                              onClick={() => onInspectFindingInHex(hit)}
                              className="inline-flex items-center gap-1 px-2.5 py-1 text-xs font-medium text-indigo-300 hover:text-white bg-indigo-950/60 hover:bg-indigo-600 border border-indigo-800/60 rounded transition-colors"
                            >
                              <Code2 className="w-3.5 h-3.5" />
                              Inspect Hex
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
