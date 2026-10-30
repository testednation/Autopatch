import React, { useMemo, useState } from 'react';
import { Plus, Search, Trash2 } from 'lucide-react';
import {
  BUILTIN_TELEMETRY_SIGNATURES,
  HEURISTIC_SUBDOMAIN_KEYWORDS,
  SeverityLevel,
  TelemetryCategory,
  TelemetrySignature,
} from '../data/telemetryDatabase';

interface SignatureDatabaseViewProps {
  customSignatures: TelemetrySignature[];
  onAddCustomSignature: (sig: Omit<TelemetrySignature, 'id'>) => void;
  onRemoveCustomSignature: (id: string) => void;
  enableHeuristics: boolean;
  onToggleHeuristics: (enabled: boolean) => void;
}

export const SignatureDatabaseView: React.FC<SignatureDatabaseViewProps> = ({
  customSignatures,
  onAddCustomSignature,
  onRemoveCustomSignature,
  enableHeuristics,
  onToggleHeuristics,
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string>('All');

  // New signature form state
  const [domainPattern, setDomainPattern] = useState('');
  const [vendor, setVendor] = useState('');
  const [category, setCategory] = useState<TelemetryCategory>('Custom Rule');
  const [severity, setSeverity] = useState<SeverityLevel>('High');
  const [description, setDescription] = useState('');

  const allSignatures = useMemo(
    () => [...customSignatures, ...BUILTIN_TELEMETRY_SIGNATURES],
    [customSignatures]
  );

  const filteredSignatures = useMemo(() => {
    return allSignatures.filter((sig) => {
      const matchesCat = selectedCategory === 'All' || sig.category === selectedCategory;
      const q = searchQuery.trim().toLowerCase();
      const matchesSearch =
        !q ||
        sig.domainPattern.toLowerCase().includes(q) ||
        sig.vendor.toLowerCase().includes(q) ||
        sig.description.toLowerCase().includes(q);
      return matchesCat && matchesSearch;
    });
  }, [allSignatures, selectedCategory, searchQuery]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const cleaned = domainPattern
      .trim()
      .toLowerCase()
      .replace(/^https?:\/\//, '')
      .replace(/\/.*$/, '');
    if (!cleaned || !cleaned.includes('.')) return;

    onAddCustomSignature({
      domainPattern: cleaned,
      vendor: vendor.trim() || 'User Custom Rule',
      category,
      severity,
      description:
        description.trim() || `Custom offline telemetry rule matching ${cleaned}`,
      builtIn: false,
    });

    setDomainPattern('');
    setVendor('');
    setDescription('');
  };

  const categories = [
    'All',
    'Mobile SDK & MMP',
    'Crash & Error Reporting',
    'Behavioral Analytics',
    'Vendor Diagnostics',
    'Ad-Tech & Attribution',
    'Custom Rule',
  ];

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left: Add Custom Offline Rule + Heuristic Settings */}
        <div className="lg:col-span-4 space-y-6">
          <form
            onSubmit={handleSubmit}
            className="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-4"
          >
            <div>
              <h2 className="text-sm font-semibold text-slate-100">
                Add Custom Domain Rule
              </h2>
              <p className="text-xs text-slate-400 mt-1">
                New rules immediately re-scan all loaded binary and APK buffers in memory.
              </p>
            </div>

            <div>
              <label htmlFor="sig-domain" className="block text-xs text-slate-300 mb-1">
                Domain or Suffix Pattern
              </label>
              <input
                id="sig-domain"
                type="text"
                required
                placeholder="e.g. telemetry.vendor-app.com"
                value={domainPattern}
                onChange={(e) => setDomainPattern(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-md px-3 py-2 text-xs font-mono text-slate-100 focus:outline-none focus:border-indigo-500"
              />
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label htmlFor="sig-vendor" className="block text-xs text-slate-300 mb-1">
                  Vendor Label
                </label>
                <input
                  id="sig-vendor"
                  type="text"
                  placeholder="e.g. Internal SDK"
                  value={vendor}
                  onChange={(e) => setVendor(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-md px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-indigo-500"
                />
              </div>

              <div>
                <label htmlFor="sig-severity" className="block text-xs text-slate-300 mb-1">
                  Severity
                </label>
                <select
                  id="sig-severity"
                  value={severity}
                  onChange={(e) => setSeverity(e.target.value as SeverityLevel)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-md px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-indigo-500"
                >
                  <option value="High">High</option>
                  <option value="Medium">Medium</option>
                  <option value="Advisory">Advisory</option>
                </select>
              </div>
            </div>

            <div>
              <label htmlFor="sig-category" className="block text-xs text-slate-300 mb-1">
                Category
              </label>
              <select
                id="sig-category"
                value={category}
                onChange={(e) => setCategory(e.target.value as TelemetryCategory)}
                className="w-full bg-slate-950 border border-slate-800 rounded-md px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-indigo-500"
              >
                <option value="Custom Rule">Custom Rule</option>
                <option value="Mobile SDK & MMP">Mobile SDK & MMP</option>
                <option value="Crash & Error Reporting">Crash & Error Reporting</option>
                <option value="Behavioral Analytics">Behavioral Analytics</option>
                <option value="Vendor Diagnostics">Vendor Diagnostics</option>
                <option value="Ad-Tech & Attribution">Ad-Tech & Attribution</option>
              </select>
            </div>

            <div>
              <label htmlFor="sig-desc" className="block text-xs text-slate-300 mb-1">
                Notes / Endpoint Purpose
              </label>
              <input
                id="sig-desc"
                type="text"
                placeholder="Optional description of what this endpoint collects"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-md px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-indigo-500"
              />
            </div>

            <button
              type="submit"
              className="w-full inline-flex items-center justify-center gap-1.5 px-4 py-2 text-xs font-semibold text-white bg-indigo-600 hover:bg-indigo-500 rounded-md transition-colors"
            >
              <Plus className="w-4 h-4" />
              Add Offline Signature & Rescan
            </button>
          </form>

          {/* Heuristic Subdomain Engine Toggle */}
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-slate-100">
                Heuristic Subdomain Engine
              </h3>
              <label className="inline-flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
                <input
                  type="checkbox"
                  checked={enableHeuristics}
                  onChange={(e) => onToggleHeuristics(e.target.checked)}
                  className="rounded border-slate-700 bg-slate-950 text-indigo-500 focus:ring-indigo-500"
                />
                {enableHeuristics ? 'Enabled' : 'Disabled'}
              </label>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              Automatically flags first-party or unlisted domains whose subdomain prefix matches
              known ingestion patterns:
            </p>
            <div className="p-3 bg-slate-950 border border-slate-800 rounded font-mono text-[11px] text-slate-300 leading-relaxed">
              {HEURISTIC_SUBDOMAIN_KEYWORDS.map((k) => `${k.trim()}.*`).join(' · ')}
            </div>
          </div>
        </div>

        {/* Right: Signature Table */}
        <div className="lg:col-span-8 bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
          <div className="p-4 border-b border-slate-800 space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <h2 className="text-sm font-semibold text-slate-100">
                Offline Telemetry Signatures ({filteredSignatures.length})
              </h2>
              <div className="relative w-64">
                <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  placeholder="Search domain or vendor..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-md pl-8 pr-3 py-1.5 text-xs text-slate-100 focus:outline-none focus:border-indigo-500"
                />
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-1 p-1 bg-slate-950 border border-slate-800 rounded-md">
              {categories.map((cat) => (
                <button
                  key={cat}
                  type="button"
                  onClick={() => setSelectedCategory(cat)}
                  className={`px-2.5 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 ${
                    selectedCategory === cat
                      ? 'bg-slate-800 text-white'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {cat}
                </button>
              ))}
            </div>
          </div>

          <div className="overflow-x-auto max-h-[580px] overflow-y-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-950/60 text-[11px] font-medium text-slate-400">
                  <th className="py-2.5 px-4">Domain Pattern</th>
                  <th className="py-2.5 px-4">Vendor & Classification</th>
                  <th className="py-2.5 px-4">Severity</th>
                  <th className="py-2.5 px-4 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70 text-xs">
                {filteredSignatures.map((sig) => (
                  <tr key={sig.id} className="hover:bg-slate-800/40">
                    <td className="py-3 px-4 font-mono font-medium text-indigo-300 whitespace-nowrap">
                      *.{sig.domainPattern}
                    </td>
                    <td className="py-3 px-4">
                      <div className="text-slate-200 font-medium">
                        {sig.vendor}
                        <span className="mx-1.5 text-slate-600">·</span>
                        <span className="text-slate-400 font-normal">{sig.category}</span>
                      </div>
                      <div className="text-slate-400 text-[11px] mt-0.5">{sig.description}</div>
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap">
                      <span
                        className={
                          sig.severity === 'High'
                            ? 'text-rose-400 font-medium'
                            : sig.severity === 'Medium'
                            ? 'text-amber-300 font-medium'
                            : 'text-slate-400'
                        }
                      >
                        {sig.severity}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-right whitespace-nowrap">
                      {!sig.builtIn ? (
                        <button
                          type="button"
                          onClick={() => onRemoveCustomSignature(sig.id)}
                          className="inline-flex items-center gap-1 text-rose-400 hover:text-rose-300 text-xs"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                          Remove
                        </button>
                      ) : (
                        <span className="text-slate-500 text-[11px]">Built-in</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};
