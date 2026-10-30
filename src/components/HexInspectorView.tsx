import React, { useMemo, useState } from 'react';
import {
  ArrowDownToLine,
  Check,
  ChevronLeft,
  ChevronRight,
  LockOpen,
  RotateCcw,
  SlidersHorizontal,
  Zap,
} from 'lucide-react';
import {
  buildReplacementBytes,
  PatchStrategy,
  ScannedBinaryFile,
  TelemetryFinding,
} from '../utils/binaryScanner';

interface HexInspectorViewProps {
  files: ScannedBinaryFile[];
  selectedFileId: string;
  onSelectFile: (id: string) => void;
  focusedFindingId: string | null;
  onSelectFinding: (finding: TelemetryFinding) => void;
  patchStrategy: PatchStrategy;
  onChangePatchStrategy: (strategy: PatchStrategy) => void;
  onToggleFindingSelection: (fileId: string, findingId: string) => void;
  onApplyPatchesToFile: (fileId: string) => void;
  onRestoreOriginalFile: (fileId: string) => void;
  onDownloadPatchedFile: (file: ScannedBinaryFile) => void;
}

const BYTES_PER_ROW = 16;
const VISIBLE_ROWS = 28; // 448 bytes per viewport window

export const HexInspectorView: React.FC<HexInspectorViewProps> = ({
  files,
  selectedFileId,
  onSelectFile,
  focusedFindingId,
  onSelectFinding,
  patchStrategy,
  onChangePatchStrategy,
  onToggleFindingSelection,
  onApplyPatchesToFile,
  onRestoreOriginalFile,
  onDownloadPatchedFile,
}) => {
  const activeFile = useMemo(
    () => files.find((f) => f.id === selectedFileId) || files[0],
    [files, selectedFileId]
  );

  const activeFinding = useMemo(() => {
    if (!activeFile) return null;
    if (focusedFindingId) {
      const found = activeFile.findings.find((f) => f.id === focusedFindingId);
      if (found) return found;
    }
    return activeFile.findings[0] || null;
  }, [activeFile, focusedFindingId]);

  const [manualBaseOffset, setManualBaseOffset] = useState<number | null>(null);
  const [viewBufferMode, setViewBufferMode] = useState<'preview' | 'original' | 'working'>('preview');

  const baseOffset = useMemo(() => {
    if (!activeFile) return 0;
    if (manualBaseOffset !== null) {
      return Math.max(
        0,
        Math.min(
          Math.floor(manualBaseOffset / BYTES_PER_ROW) * BYTES_PER_ROW,
          Math.max(0, activeFile.size - BYTES_PER_ROW * 4)
        )
      );
    }
    if (activeFinding) {
      const aligned = Math.floor(activeFinding.offset / BYTES_PER_ROW) * BYTES_PER_ROW;
      return Math.max(0, aligned - BYTES_PER_ROW * 3);
    }
    return 0;
  }, [activeFile, activeFinding, manualBaseOffset]);

  const previewBuffer = useMemo(() => {
    if (!activeFile) return new Uint8Array(0);
    if (viewBufferMode === 'original') return activeFile.originalBuffer;
    if (viewBufferMode === 'working') return activeFile.workingBuffer;

    const buf = new Uint8Array(activeFile.originalBuffer.byteLength);
    buf.set(activeFile.originalBuffer);
    for (const f of activeFile.findings) {
      if (f.selected) {
        const rep = buildReplacementBytes(f, patchStrategy);
        buf.set(rep, f.offset);
      }
    }
    return buf;
  }, [activeFile, patchStrategy, viewBufferMode]);

  const visibleFindingMap = useMemo(() => {
    const map = new Map<number, { finding: TelemetryFinding; isFocused: boolean }>();
    if (!activeFile) return map;
    const endOffset = baseOffset + VISIBLE_ROWS * BYTES_PER_ROW;

    for (const f of activeFile.findings) {
      const fEnd = f.offset + f.byteLength;
      if (fEnd >= baseOffset && f.offset <= endOffset) {
        const isFocused = activeFinding?.id === f.id;
        const start = Math.max(baseOffset, f.offset);
        const end = Math.min(endOffset, fEnd);
        for (let pos = start; pos < end; pos++) {
          map.set(pos, { finding: f, isFocused });
        }
      }
    }
    return map;
  }, [activeFile, activeFinding, baseOffset]);

  if (!activeFile) {
    return (
      <div className="border border-slate-800 bg-slate-900/50 rounded-lg p-12 text-center">
        <p className="text-slate-300 font-medium">No binary file loaded in workspace.</p>
        <p className="text-sm text-slate-500 mt-1">
          Drop an executable or load the sample telemetry binary suite to inspect raw offsets.
        </p>
      </div>
    );
  }

  const hexRows: number[] = [];
  for (let r = 0; r < VISIBLE_ROWS; r++) {
    const rowOff = baseOffset + r * BYTES_PER_ROW;
    if (rowOff < activeFile.size) {
      hexRows.push(rowOff);
    }
  }

  const selectedCount = activeFile.findings.filter((f) => f.selected).length;

  const replacementPreviewInfo = useMemo(() => {
    if (!activeFinding) return { rawEncoded: '', decodedRuntime: '' };
    const bytes = buildReplacementBytes(activeFinding, patchStrategy);
    let rawEncoded = '';
    for (let i = 0; i < bytes.length; i++) {
      const b = bytes[i];
      if (b === 0) rawEncoded += '·';
      else if (b >= 32 && b <= 126) rawEncoded += String.fromCharCode(b);
      else rawEncoded += `\\x${b.toString(16).toUpperCase().padStart(2, '0')}`;
    }

    let decodedRuntime = rawEncoded;
    if (activeFinding.encoding === 'XOR-8' && activeFinding.xorKey !== undefined) {
      let dec = '';
      for (let i = 0; i < bytes.length; i++) {
        const d = bytes[i] ^ activeFinding.xorKey;
        dec += d === 0 ? '·' : d >= 32 && d <= 126 ? String.fromCharCode(d) : '.';
      }
      decodedRuntime = dec;
    } else if (activeFinding.encoding === 'Base64') {
      decodedRuntime = 'Base64("https://0.0.0.0") + null pad';
    } else if (activeFinding.encoding === 'Reversed') {
      decodedRuntime = 'Reversed("https://0.0.0.0///...")';
    } else if (activeFinding.encoding === 'ROT13') {
      decodedRuntime = 'ROT13("https://0.0.0.0") + null pad';
    }

    return { rawEncoded, decodedRuntime };
  }, [activeFinding, patchStrategy]);

  return (
    <div className="space-y-6">
      {/* Top Control Bar */}
      <div className="flex flex-wrap items-center justify-between gap-4 p-4 bg-slate-900 border border-slate-800 rounded-lg">
        <div className="flex flex-wrap items-center gap-4">
          <div>
            <label htmlFor="hex-file-select" className="block text-xs text-slate-400 mb-1">
              Target Binary
            </label>
            <select
              id="hex-file-select"
              value={activeFile.id}
              onChange={(e) => {
                onSelectFile(e.target.value);
                setManualBaseOffset(null);
              }}
              className="bg-slate-950 border border-slate-800 rounded-md px-3 py-1.5 text-sm text-slate-100 font-mono focus:outline-none focus:border-indigo-500"
            >
              {files.map((f) => (
                <option key={f.id} value={f.id}>
                  {f.name} ({f.findings.length} hits · {f.obfuscatedHitsCount} obf ·{' '}
                  {(f.size / 1024).toFixed(1)} KB)
                </option>
              ))}
            </select>
          </div>

          <div>
            <label htmlFor="patch-strategy-select" className="block text-xs text-slate-400 mb-1">
              Hex Patch Strategy (Preserves Exact Byte Length & Cipher Transform)
            </label>
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
                Loopback (0.0.0.0 + Cipher Pad)
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
                Full Null / XOR Key Wipe
              </button>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {activeFile.isModified && (
            <button
              type="button"
              onClick={() => onRestoreOriginalFile(activeFile.id)}
              className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 rounded-md transition-colors whitespace-nowrap shrink-0"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              Restore Original Bytes
            </button>
          )}
          <button
            type="button"
            onClick={() => onApplyPatchesToFile(activeFile.id)}
            disabled={selectedCount === 0}
            className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-semibold text-white bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 rounded-md transition-colors whitespace-nowrap shrink-0"
          >
            <Zap className="w-3.5 h-3.5" />
            Commit & Repack ({selectedCount})
          </button>
          <button
            type="button"
            onClick={() => onDownloadPatchedFile(activeFile)}
            className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-semibold text-slate-950 bg-emerald-400 hover:bg-emerald-300 rounded-md transition-colors whitespace-nowrap shrink-0"
          >
            <ArrowDownToLine className="w-3.5 h-3.5" />
            Save Repacked {activeFile.name}
          </button>
        </div>
      </div>

      {/* PE Section / APK Entry & Shannon Entropy Diagnostic Bar */}
      {activeFile.sections.length > 0 && (
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-3.5 flex flex-wrap items-center justify-between gap-4 text-xs">
          <div className="flex flex-wrap items-center gap-4">
            <span className="font-semibold text-slate-200">
              {activeFile.isAPK
                ? 'APK Archive Entries (DEX / AXML / Native .so):'
                : activeFile.isDEX
                ? 'Dalvik DEX Sections:'
                : 'PE Section Entropy & Obfuscation Diagnostics:'}
            </span>
            {activeFile.sections.map((sec) => (
              <button
                key={sec.name}
                type="button"
                onClick={() => setManualBaseOffset(sec.rawAddress)}
                className="font-mono text-slate-300 hover:text-indigo-300 transition-colors"
                title={`Jump to ${sec.name} at 0x${sec.rawAddress.toString(16)}`}
              >
                <span className="text-indigo-300 font-semibold">{sec.name}</span>{' '}
                <span className="text-slate-500">
                  (0x{sec.rawAddress.toString(16).toUpperCase()} · {sec.entropy.toFixed(2)} b/B)
                </span>
              </button>
            ))}
          </div>
          <div className="font-mono text-slate-400">
            {activeFile.isAPK && (
              <span className="text-emerald-400 mr-3">
                Auto-Updates DEX SHA-1/Adler-32 & ZIP CRC-32
              </span>
            )}
            Overall Entropy:{' '}
            <span className="text-slate-200">{activeFile.overallEntropy.toFixed(2)} b/B</span>
            {activeFile.packerDetected && (
              <>
                <span className="mx-2">·</span>
                <span className="text-amber-300">{activeFile.packerDetected}</span>
              </>
            )}
          </div>
        </div>
      )}

      {/* Main Split: Left Offset Directory + Right Hex Matrix & Byte Diff */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left Column: Offset Jump Table (4 cols) */}
        <div className="lg:col-span-4 bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-slate-100">
              Telemetry String Offsets ({activeFile.findings.length})
            </h2>
            <span className="text-xs text-slate-400 font-mono tabular-nums">
              {activeFile.architecture}
            </span>
          </div>

          <div className="divide-y divide-slate-800/70 max-h-[620px] overflow-y-auto">
            {activeFile.findings.length === 0 ? (
              <div className="p-6 text-sm text-slate-400 text-center">
                No telemetry strings detected in this binary.
              </div>
            ) : (
              activeFile.findings.map((f) => {
                const isFocused = activeFinding?.id === f.id;
                const isObfuscated = f.encoding !== 'ASCII' && f.encoding !== 'UTF-16LE';

                return (
                  <div
                    key={f.id}
                    onClick={() => {
                      onSelectFinding(f);
                      setManualBaseOffset(null);
                    }}
                    className={`p-3.5 cursor-pointer transition-colors ${
                      isFocused ? 'bg-indigo-950/50' : 'hover:bg-slate-800/50'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2 min-w-0">
                        <input
                          type="checkbox"
                          checked={f.selected}
                          onChange={(e) => {
                            e.stopPropagation();
                            onToggleFindingSelection(activeFile.id, f.id);
                          }}
                          aria-label={`Select ${f.domain} at offset 0x${f.offset.toString(16)}`}
                          className="rounded border-slate-700 bg-slate-950 text-indigo-500 focus:ring-indigo-500"
                        />
                        <span className="font-mono text-xs font-semibold text-indigo-300 tabular-nums">
                          0x{f.offset.toString(16).toUpperCase().padStart(8, '0')}
                        </span>
                        <span className="text-xs text-slate-500">·</span>
                        <span className="text-xs text-slate-400 font-mono">{f.sectionName}</span>
                      </div>
                      <span
                        className={`text-xs font-mono tabular-nums shrink-0 inline-flex items-center gap-1 ${
                          isObfuscated ? 'text-amber-300 font-semibold' : 'text-slate-400'
                        }`}
                      >
                        {isObfuscated && <LockOpen className="w-3 h-3" />}
                        {f.encoding} · {f.byteLength}B
                      </span>
                    </div>

                    <p className="mt-1.5 text-xs font-mono text-slate-200 truncate" title={f.rawString}>
                      {f.rawString}
                    </p>

                    {f.obfuscationDetail && (
                      <p className="mt-0.5 text-[11px] font-mono text-amber-300/80 truncate">
                        {f.obfuscationDetail}
                      </p>
                    )}

                    <div className="mt-1 flex items-center justify-between text-[11px] text-slate-400">
                      <span>
                        {f.vendor} · {f.category}
                      </span>
                      {f.patched ? (
                        <span className="text-emerald-400 font-medium inline-flex items-center gap-1">
                          <Check className="w-3 h-3" /> Patched
                        </span>
                      ) : f.selected ? (
                        <span className="text-amber-300">Staged</span>
                      ) : (
                        <span className="text-slate-500">Skipped</span>
                      )}
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Right Column: Live Hex Matrix & In-Place Diff Verification (8 cols) */}
        <div className="lg:col-span-8 space-y-4">
          {/* Selected Finding Byte-Length & Deobfuscation Invariant Card */}
          {activeFinding && (
            <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="text-xs text-slate-400">
                  <span className="text-slate-200 font-semibold">Selected Offset Inspection</span>
                  <span className="mx-2">·</span>
                  <span className="font-mono text-indigo-300">
                    0x{activeFinding.offset.toString(16).toUpperCase().padStart(8, '0')} – 0x
                    {(activeFinding.offset + activeFinding.byteLength - 1)
                      .toString(16)
                      .toUpperCase()
                      .padStart(8, '0')}
                  </span>
                  <span className="mx-2">·</span>
                  <span className="text-amber-300 font-mono">
                    {activeFinding.obfuscationDetail || activeFinding.encoding} ({activeFinding.byteLength} bytes)
                  </span>
                </div>
                <span className="text-xs text-emerald-400 font-mono">
                  Size Delta: 0 bytes (PE & Cipher Safe)
                </span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
                <div className="p-2.5 bg-slate-950 border border-slate-800 rounded space-y-1">
                  <div className="text-slate-400 flex items-center justify-between">
                    <span>Deobfuscated Telemetry Endpoint</span>
                    <span>{activeFinding.byteLength} bytes</span>
                  </div>
                  <div className="text-rose-300 break-all">{activeFinding.rawString}</div>
                  {activeFinding.encodedPreview && (
                    <div className="text-[11px] text-slate-500 break-all pt-1 border-t border-slate-900">
                      Raw Cipher Bytes: {activeFinding.encodedPreview}
                    </div>
                  )}
                </div>
                <div className="p-2.5 bg-slate-950 border border-slate-800 rounded space-y-1">
                  <div className="text-slate-400 flex items-center justify-between">
                    <span>Format-Preserving Replacement ({patchStrategy})</span>
                    <span>{activeFinding.byteLength} bytes</span>
                  </div>
                  <div className="text-emerald-300 break-all">
                    {replacementPreviewInfo.rawEncoded}
                  </div>
                  {activeFinding.encoding !== 'ASCII' &&
                    activeFinding.encoding !== 'UTF-16LE' && (
                      <div className="text-[11px] text-indigo-300 break-all pt-1 border-t border-slate-900">
                        Decodes at runtime to: {replacementPreviewInfo.decodedRuntime}
                      </div>
                    )}
                </div>
              </div>
            </div>
          )}

          {/* Hex Matrix Viewer */}
          <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
            <div className="px-4 py-3 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-3">
                <SlidersHorizontal className="w-4 h-4 text-slate-400" />
                <span className="text-xs font-medium text-slate-300">
                  Buffer View:
                </span>
                <div className="flex items-center gap-1 p-0.5 bg-slate-950 border border-slate-800 rounded">
                  <button
                    type="button"
                    onClick={() => setViewBufferMode('preview')}
                    className={`px-2.5 py-1 text-xs rounded transition-colors whitespace-nowrap shrink-0 ${
                      viewBufferMode === 'preview'
                        ? 'bg-slate-800 text-white font-medium'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    Live Patch Preview
                  </button>
                  <button
                    type="button"
                    onClick={() => setViewBufferMode('original')}
                    className={`px-2.5 py-1 text-xs rounded transition-colors whitespace-nowrap shrink-0 ${
                      viewBufferMode === 'original'
                        ? 'bg-slate-800 text-white font-medium'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    Original Bytes
                  </button>
                  <button
                    type="button"
                    onClick={() => setViewBufferMode('working')}
                    className={`px-2.5 py-1 text-xs rounded transition-colors whitespace-nowrap shrink-0 ${
                      viewBufferMode === 'working'
                        ? 'bg-slate-800 text-white font-medium'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    Committed Binary
                  </button>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() =>
                    setManualBaseOffset(Math.max(0, baseOffset - BYTES_PER_ROW * 10))
                  }
                  disabled={baseOffset === 0}
                  className="p-1.5 text-slate-400 hover:text-slate-100 bg-slate-950 border border-slate-800 rounded disabled:opacity-40"
                  title="Previous 160 bytes"
                >
                  <ChevronLeft className="w-4 h-4" />
                </button>
                <span className="text-xs font-mono text-slate-400 tabular-nums">
                  0x{baseOffset.toString(16).toUpperCase().padStart(8, '0')}
                </span>
                <button
                  type="button"
                  onClick={() =>
                    setManualBaseOffset(
                      Math.min(
                        Math.max(0, activeFile.size - BYTES_PER_ROW * 8),
                        baseOffset + BYTES_PER_ROW * 10
                      )
                    )
                  }
                  disabled={baseOffset + VISIBLE_ROWS * BYTES_PER_ROW >= activeFile.size}
                  className="p-1.5 text-slate-400 hover:text-slate-100 bg-slate-950 border border-slate-800 rounded disabled:opacity-40"
                  title="Next 160 bytes"
                >
                  <ChevronRight className="w-4 h-4" />
                </button>
              </div>
            </div>

            {/* Column Header */}
            <div className="grid grid-cols-12 px-4 py-2 bg-slate-950/80 border-b border-slate-800 text-[11px] font-mono text-slate-500 select-none">
              <div className="col-span-2">OFFSET</div>
              <div className="col-span-7">
                00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F
              </div>
              <div className="col-span-3 text-right">DECODED ASCII</div>
            </div>

            {/* Hex Rows */}
            <div className="p-4 bg-slate-950 font-mono text-xs space-y-1 overflow-x-auto">
              {hexRows.map((rowOffset) => {
                const cells: React.ReactNode[] = [];
                const asciiCells: React.ReactNode[] = [];

                for (let col = 0; col < BYTES_PER_ROW; col++) {
                  const bytePos = rowOffset + col;
                  if (bytePos >= activeFile.size) {
                    cells.push(
                      <span key={col} className="inline-block w-6 text-slate-800">
                        {'  '}
                      </span>
                    );
                    continue;
                  }

                  const origByte = activeFile.originalBuffer[bytePos];
                  const currByte = previewBuffer[bytePos];
                  const hit = visibleFindingMap.get(bytePos);
                  const isChanged = origByte !== currByte;

                  let cellClass = 'text-slate-400';
                  if (hit) {
                    if (isChanged) {
                      cellClass = hit.isFocused
                        ? 'bg-emerald-500/30 text-emerald-200 font-semibold'
                        : 'bg-emerald-500/15 text-emerald-300';
                    } else {
                      cellClass = hit.isFocused
                        ? 'bg-rose-500/30 text-rose-200 font-semibold'
                        : 'bg-amber-500/15 text-amber-300';
                    }
                  }

                  cells.push(
                    <span
                      key={col}
                      className={`inline-block w-[22px] text-center rounded-xs ${cellClass} ${
                        col === 7 ? 'mr-2' : ''
                      }`}
                      title={`Offset 0x${bytePos.toString(16).toUpperCase()} | Orig: 0x${origByte
                        .toString(16)
                        .padStart(2, '0')} | Curr: 0x${currByte.toString(16).padStart(2, '0')}`}
                    >
                      {currByte.toString(16).toUpperCase().padStart(2, '0')}
                    </span>
                  );

                  const charStr =
                    currByte >= 0x20 && currByte <= 0x7e
                      ? String.fromCharCode(currByte)
                      : '·';

                  asciiCells.push(
                    <span
                      key={col}
                      className={
                        hit
                          ? isChanged
                            ? 'text-emerald-300 font-semibold'
                            : 'text-rose-300 font-semibold'
                          : 'text-slate-500'
                      }
                    >
                      {charStr}
                    </span>
                  );
                }

                return (
                  <div
                    key={rowOffset}
                    className="grid grid-cols-12 items-center hover:bg-slate-900/60 px-1 py-0.5 rounded-xs"
                  >
                    <div className="col-span-2 text-slate-500 select-none tabular-nums">
                      0x{rowOffset.toString(16).toUpperCase().padStart(8, '0')}
                    </div>
                    <div className="col-span-7 whitespace-nowrap">{cells}</div>
                    <div className="col-span-3 text-right tracking-widest whitespace-nowrap">
                      {asciiCells}
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Checksum & Automatic Repacker Footer */}
            <div className="px-4 py-3 bg-slate-900 border-t border-slate-800 flex flex-wrap items-center justify-between gap-2 text-xs font-mono text-slate-400">
              <div className="truncate">
                <span className="text-slate-500">Original SHA-256: </span>
                <span className="text-slate-300">{activeFile.originalSha256.slice(0, 20)}…</span>
              </div>
              {activeFile.repackInfo && (
                <div className="truncate text-emerald-400">
                  <span>Auto-Repack: {activeFile.repackInfo.summary}</span>
                </div>
              )}
              <div className="truncate">
                <span className="text-slate-500">Repacked SHA-256: </span>
                <span
                  className={
                    activeFile.isModified ? 'text-emerald-400 font-medium' : 'text-slate-300'
                  }
                >
                  {(activeFile.repackInfo?.repackedSha256 || activeFile.workingSha256).slice(
                    0,
                    20
                  )}
                  …
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
