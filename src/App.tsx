/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useEffect, useState } from 'react';
import { RotateCcw } from 'lucide-react';
import { TelemetrySignature } from './data/telemetryDatabase';
import {
  applyHexPatchesToFile,
  createSampleBinarySuite,
  PatchStrategy,
  restoreOriginalFile,
  scanBinaryBuffer,
  ScannedBinaryFile,
  TelemetryFinding,
} from './utils/binaryScanner';
import { ScannerReportView } from './components/ScannerReportView';
import { HexInspectorView } from './components/HexInspectorView';
import { HostsFirewallView } from './components/HostsFirewallView';
import { SignatureDatabaseView } from './components/SignatureDatabaseView';

type ActiveTab = 'scanner' | 'hex' | 'blocker' | 'signatures';

export default function App() {
  const [activeTab, setActiveTab] = useState<ActiveTab>('scanner');
  const [files, setFiles] = useState<ScannedBinaryFile[]>([]);
  const [selectedFileId, setSelectedFileId] = useState<string | 'ALL'>('ALL');
  const [hexFileId, setHexFileId] = useState<string>('');
  const [focusedFindingId, setFocusedFindingId] = useState<string | null>(null);
  const [patchStrategy, setPatchStrategy] = useState<PatchStrategy>('loopback');
  const [customSignatures, setCustomSignatures] = useState<TelemetrySignature[]>([]);
  const [enableHeuristics, setEnableHeuristics] = useState<boolean>(true);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  const showNotice = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => {
      setToastMessage((prev) => (prev === msg ? null : prev));
    }, 3200);
  };

  // Load the realistic sample PE32+ binary suite on initial mount so the user can test immediately
  useEffect(() => {
    let mounted = true;
    createSampleBinarySuite().then((suite) => {
      if (!mounted) return;
      setFiles(suite);
      if (suite.length > 0) {
        setHexFileId(suite[0].id);
        if (suite[0].findings.length > 0) {
          setFocusedFindingId(suite[0].findings[0].id);
        }
      }
    });
    return () => {
      mounted = false;
    };
  }, []);

  // Re-scan existing original buffers whenever customSignatures or enableHeuristics change
  const rescanLoadedBuffers = async (
    nextCustomSigs: TelemetrySignature[],
    nextHeuristics: boolean
  ) => {
    if (files.length === 0) return;
    setIsScanning(true);
    const updated: ScannedBinaryFile[] = [];
    for (const f of files) {
      const rescanned = await scanBinaryBuffer(
        f.id,
        f.name,
        f.relativePath,
        f.originalBuffer,
        nextCustomSigs,
        nextHeuristics
      );
      updated.push(rescanned);
    }
    setFiles(updated);
    setIsScanning(false);
  };

  const handleLoadSampleSuite = async () => {
    setIsScanning(true);
    const suite = await createSampleBinarySuite();
    setFiles(suite);
    setSelectedFileId('ALL');
    if (suite.length > 0) {
      setHexFileId(suite[0].id);
      setFocusedFindingId(suite[0].findings[0]?.id || null);
    }
    setIsScanning(false);
    showNotice('Loaded 3 sample PE32+ binaries with ASCII & UTF-16LE telemetry strings.');
  };

  const handleFilesDropped = async (
    incoming: { file: File; relativePath: string }[]
  ) => {
    setIsScanning(true);
    const newlyScanned: ScannedBinaryFile[] = [];

    for (let i = 0; i < incoming.length; i++) {
      const { file, relativePath } = incoming[i];
      // Skip tiny empty files or huge files > 150MB to keep browser memory responsive
      if (file.size === 0 || file.size > 150 * 1024 * 1024) continue;
      const arrayBuf = await file.arrayBuffer();
      const uint8 = new Uint8Array(arrayBuf);
      const id = `user-${Date.now()}-${i}`;
      const scanned = await scanBinaryBuffer(
        id,
        file.name,
        relativePath,
        uint8,
        customSignatures,
        enableHeuristics
      );
      newlyScanned.push(scanned);
    }

    if (newlyScanned.length > 0) {
      setFiles(newlyScanned);
      setSelectedFileId('ALL');
      setHexFileId(newlyScanned[0].id);
      setFocusedFindingId(newlyScanned[0].findings[0]?.id || null);
      const totalHits = newlyScanned.reduce((acc, f) => acc + f.findings.length, 0);
      showNotice(
        `Scanned ${newlyScanned.length} ${
          newlyScanned.length === 1 ? 'file' : 'files'
        } offline — detected ${totalHits} telemetry endpoints.`
      );
    }
    setIsScanning(false);
  };

  const handleToggleFindingSelection = (fileId: string, findingId: string) => {
    setFiles((prev) =>
      prev.map((file) => {
        if (file.id !== fileId) return file;
        return {
          ...file,
          findings: file.findings.map((f) =>
            f.id === findingId ? { ...f, selected: !f.selected } : f
          ),
        };
      })
    );
  };

  const handleToggleAllFindingsInView = (
    targetFindings: TelemetryFinding[],
    selected: boolean
  ) => {
    const idSet = new Set(targetFindings.map((t) => t.id));
    setFiles((prev) =>
      prev.map((file) => ({
        ...file,
        findings: file.findings.map((f) =>
          idSet.has(f.id) ? { ...f, selected } : f
        ),
      }))
    );
  };

  const handleApplyPatchesToFile = async (fileId: string) => {
    const target = files.find((f) => f.id === fileId);
    if (!target) return;
    const patchedFile = await applyHexPatchesToFile(target, patchStrategy);
    setFiles((prev) => prev.map((f) => (f.id === fileId ? patchedFile : f)));
    const count = patchedFile.findings.filter((x) => x.patched).length;
    showNotice(
      `Committed ${count} in-place hex ${
        count === 1 ? 'patch' : 'patches'
      } to ${patchedFile.name} (0 byte length delta).`
    );
  };

  const handleRestoreOriginalFile = (fileId: string) => {
    setFiles((prev) =>
      prev.map((f) => (f.id === fileId ? restoreOriginalFile(f) : f))
    );
    showNotice('Restored original untouched binary bytes.');
  };

  const handlePatchAllFiles = async () => {
    const updated: ScannedBinaryFile[] = [];
    let totalPatched = 0;
    for (const f of files) {
      if (f.findings.some((x) => x.selected)) {
        const pf = await applyHexPatchesToFile(f, patchStrategy);
        totalPatched += pf.findings.filter((x) => x.patched).length;
        updated.push(pf);
      } else {
        updated.push(f);
      }
    }
    setFiles(updated);
    showNotice(
      `Hex-patched ${totalPatched} telemetry occurrences across ${
        updated.filter((x) => x.isModified).length
      } binaries.`
    );
  };

  const modifiedFilesCount = files.filter((f) => f.isModified).length;
  const patchedFindingsCount = files.reduce(
    (acc, f) => acc + f.findings.filter((x) => x.patched).length,
    0
  );

  const handleRestoreAllFiles = () => {
    setFiles((prev) =>
      prev.map((f) => {
        const restored = restoreOriginalFile(f);
        return {
          ...restored,
          findings: restored.findings.map((finding) => ({
            ...finding,
            selected: true,
            patched: false,
          })),
        };
      })
    );
    showNotice(
      'Reverted workspace: restored all binaries to their original untouched bytes and SHA-256 checksums.'
    );
  };

  const handleDownloadPatchedFile = async (file: ScannedBinaryFile) => {
    // If user hasn't clicked Commit yet, apply selected patches on the fly so downloaded file is patched
    const finalFile = file.isModified
      ? file
      : await applyHexPatchesToFile(file, patchStrategy);

    if (!file.isModified) {
      setFiles((prev) => prev.map((f) => (f.id === file.id ? finalFile : f)));
    }

    const copy = new Uint8Array(finalFile.workingBuffer.byteLength);
    copy.set(finalFile.workingBuffer);
    const blob = new Blob([copy.buffer], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = finalFile.name;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleDownloadAllPatchedFiles = async () => {
    for (const f of files) {
      if (f.isModified || f.findings.some((x) => x.selected)) {
        await handleDownloadPatchedFile(f);
      }
    }
  };

  const handleInspectFindingInHex = (finding: TelemetryFinding) => {
    setHexFileId(finding.fileId);
    setFocusedFindingId(finding.id);
    setActiveTab('hex');
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col">
      {/* Main Header */}
      <header className="flex items-center justify-between gap-8 px-6 py-4 border-b border-slate-800 bg-slate-950/90 sticky top-0 z-30 backdrop-blur-xs">
        {/* Zone 1: Single text element wordmark */}
        <a
          href="#scanner"
          onClick={(e) => {
            e.preventDefault();
            setActiveTab('scanner');
          }}
          className="text-lg font-bold tracking-tight text-slate-100 whitespace-nowrap shrink-0"
        >
          NullRoute
        </a>

        {/* Zone 2: 4 concise single-line text navigation links */}
        <nav className="flex items-center gap-6 text-sm font-medium text-slate-400 overflow-x-auto">
          <a
            href="#scanner"
            onClick={(e) => {
              e.preventDefault();
              setActiveTab('scanner');
            }}
            className={`transition-colors whitespace-nowrap shrink-0 ${
              activeTab === 'scanner'
                ? 'text-white underline underline-offset-8 decoration-indigo-500 decoration-2'
                : 'hover:text-slate-200'
            }`}
          >
            Scanner & Report
          </a>
          <a
            href="#hex"
            onClick={(e) => {
              e.preventDefault();
              setActiveTab('hex');
            }}
            className={`transition-colors whitespace-nowrap shrink-0 ${
              activeTab === 'hex'
                ? 'text-white underline underline-offset-8 decoration-indigo-500 decoration-2'
                : 'hover:text-slate-200'
            }`}
          >
            Hex Inspector
          </a>
          <a
            href="#blocker"
            onClick={(e) => {
              e.preventDefault();
              setActiveTab('blocker');
            }}
            className={`transition-colors whitespace-nowrap shrink-0 ${
              activeTab === 'blocker'
                ? 'text-white underline underline-offset-8 decoration-indigo-500 decoration-2'
                : 'hover:text-slate-200'
            }`}
          >
            Hosts & Firewall
          </a>
          <a
            href="#signatures"
            onClick={(e) => {
              e.preventDefault();
              setActiveTab('signatures');
            }}
            className={`transition-colors whitespace-nowrap shrink-0 ${
              activeTab === 'signatures'
                ? 'text-white underline underline-offset-8 decoration-indigo-500 decoration-2'
                : 'hover:text-slate-200'
            }`}
          >
            Signature Database
          </a>
        </nav>

        {/* Zone 3: Primary Workspace Actions */}
        <div className="flex items-center gap-2.5 shrink-0">
          <button
            type="button"
            onClick={handleRestoreAllFiles}
            disabled={modifiedFilesCount === 0}
            title={
              modifiedFilesCount > 0
                ? `Undo ${patchedFindingsCount} applied hex patches across ${modifiedFilesCount} binaries`
                : 'No applied patches to revert'
            }
            className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium text-slate-200 bg-slate-900 hover:bg-slate-800 border border-slate-700 disabled:opacity-40 disabled:pointer-events-none rounded-lg transition-colors whitespace-nowrap shrink-0"
          >
            <RotateCcw className="w-3.5 h-3.5 text-amber-400" />
            <span>
              Revert Workspace
              {modifiedFilesCount > 0 ? ` (${modifiedFilesCount})` : ''}
            </span>
          </button>

          <button
            type="button"
            onClick={handlePatchAllFiles}
            className="px-4 py-2 text-xs font-semibold text-white bg-indigo-600 hover:bg-indigo-500 rounded-lg transition-colors whitespace-nowrap shrink-0"
          >
            Patch All Binaries
          </button>
        </div>
      </header>

      {/* Main Content Container */}
      <main className="flex-1 max-w-[1400px] w-full mx-auto px-6 py-6">
        {toastMessage && (
          <div className="mb-4 px-4 py-2.5 bg-indigo-950/90 border border-indigo-700/70 rounded-lg text-xs text-indigo-200 flex items-center justify-between">
            <span>{toastMessage}</span>
            <button
              type="button"
              onClick={() => setToastMessage(null)}
              className="text-indigo-400 hover:text-white ml-4"
            >
              Dismiss
            </button>
          </div>
        )}

        {activeTab === 'scanner' && (
          <ScannerReportView
            files={files}
            selectedFileId={selectedFileId}
            onSelectFile={setSelectedFileId}
            patchStrategy={patchStrategy}
            onChangePatchStrategy={setPatchStrategy}
            onFilesDropped={handleFilesDropped}
            onLoadSampleSuite={handleLoadSampleSuite}
            onClearAllFiles={() => setFiles([])}
            onToggleFindingSelection={handleToggleFindingSelection}
            onToggleAllFindingsInView={handleToggleAllFindingsInView}
            onPatchAllFiles={handlePatchAllFiles}
            onRestoreAllFiles={handleRestoreAllFiles}
            onDownloadPatchedFile={handleDownloadPatchedFile}
            onDownloadAllPatchedFiles={handleDownloadAllPatchedFiles}
            onInspectFindingInHex={handleInspectFindingInHex}
            onNavigateToBlocker={() => setActiveTab('blocker')}
            isScanning={isScanning}
          />
        )}

        {activeTab === 'hex' && (
          <HexInspectorView
            files={files}
            selectedFileId={hexFileId || files[0]?.id || ''}
            onSelectFile={(id) => {
              setHexFileId(id);
              const target = files.find((f) => f.id === id);
              setFocusedFindingId(target?.findings[0]?.id || null);
            }}
            focusedFindingId={focusedFindingId}
            onSelectFinding={(f) => setFocusedFindingId(f.id)}
            patchStrategy={patchStrategy}
            onChangePatchStrategy={setPatchStrategy}
            onToggleFindingSelection={handleToggleFindingSelection}
            onApplyPatchesToFile={handleApplyPatchesToFile}
            onRestoreOriginalFile={handleRestoreOriginalFile}
            onDownloadPatchedFile={handleDownloadPatchedFile}
          />
        )}

        {activeTab === 'blocker' && (
          <HostsFirewallView
            files={files}
            onToggleFindingSelection={handleToggleFindingSelection}
            onToggleDomainSelection={(domain, selected) => {
              setFiles((prev) =>
                prev.map((file) => ({
                  ...file,
                  findings: file.findings.map((f) =>
                    f.domain === domain ? { ...f, selected } : f
                  ),
                }))
              );
            }}
            onSetAllFindingsSelected={(selected) => {
              setFiles((prev) =>
                prev.map((file) => ({
                  ...file,
                  findings: file.findings.map((f) => ({ ...f, selected })),
                }))
              );
            }}
          />
        )}

        {activeTab === 'signatures' && (
          <SignatureDatabaseView
            customSignatures={customSignatures}
            onAddCustomSignature={(newSig) => {
              const created: TelemetrySignature = {
                ...newSig,
                id: `custom-${Date.now()}`,
              };
              const next = [created, ...customSignatures];
              setCustomSignatures(next);
              rescanLoadedBuffers(next, enableHeuristics);
              showNotice(`Added custom signature *.${created.domainPattern} and rescanned buffers.`);
            }}
            onRemoveCustomSignature={(id) => {
              const next = customSignatures.filter((s) => s.id !== id);
              setCustomSignatures(next);
              rescanLoadedBuffers(next, enableHeuristics);
            }}
            enableHeuristics={enableHeuristics}
            onToggleHeuristics={(enabled) => {
              setEnableHeuristics(enabled);
              rescanLoadedBuffers(customSignatures, enabled);
            }}
          />
        )}
      </main>

      {/* Quiet Footer */}
      <footer className="border-t border-slate-900 px-6 py-4 text-xs text-slate-500 flex flex-wrap items-center justify-between gap-4 max-w-[1400px] w-full mx-auto">
        <span>
          NullRoute Offline Binary Telemetry Auditor · Local ArrayBuffer Execution (Zero Network
          Calls)
        </span>
        <span>
          Preserves PE32/PE32+ section offsets via strict byte-length null padding
        </span>
      </footer>
    </div>
  );
}
