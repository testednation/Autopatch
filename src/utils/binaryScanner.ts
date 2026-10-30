import {
  BUILTIN_TELEMETRY_SIGNATURES,
  HEURISTIC_SUBDOMAIN_KEYWORDS,
  SAFE_DOMAIN_ALLOWLIST,
  SeverityLevel,
  TelemetryCategory,
  TelemetrySignature,
} from '../data/telemetryDatabase';

export type StringEncoding =
  | 'ASCII'
  | 'UTF-16LE'
  | 'DEX-MUTF8'
  | 'XOR-8'
  | 'Base64'
  | 'Reversed'
  | 'ROT13'
  | 'Hex-Encoded';

export type PatchStrategy = 'loopback' | 'nxdomain' | 'null_wipe';

export interface TelemetryFinding {
  id: string;
  fileId: string;
  fileName: string;
  filePath: string;
  offset: number; // Exact byte offset in the binary
  byteLength: number; // Exact length in bytes
  encoding: StringEncoding;
  obfuscationDetail?: string; // e.g. "XOR Key 0x5A", "Base64 (RFC 4648)", "DEX String Pool (ULEB128)"
  xorKey?: number; // Present when encoding === 'XOR-8'
  sectionName: string; // e.g. ".rdata", "classes.dex", "AndroidManifest.xml", "lib/arm64-v8a/lib.so"
  rawString: string; // Deobfuscated / readable telemetry URL or domain
  encodedPreview?: string; // Raw encoded representation in the binary
  domain: string; // Extracted domain
  vendor: string;
  category: TelemetryCategory;
  severity: SeverityLevel;
  description: string;
  selected: boolean; // Whether marked for hex patching
  patched: boolean; // Whether already patched in the working buffer
  originalBytes: Uint8Array;
}

export interface PESectionInfo {
  name: string;
  virtualAddress: number;
  virtualSize: number;
  rawAddress: number;
  rawSize: number;
  entropy: number; // Shannon entropy (0.00 - 8.00 bits/byte)
  zipLocalHeaderOffset?: number;
  zipCentralHeaderOffset?: number;
  isDexEntry?: boolean;
}

export interface RepackReportInfo {
  repackedAt: string;
  format: 'APK-ZipAligned' | 'DEX-Repaired' | 'PE-Checksum-Updated' | 'Raw-Patched';
  zipAligned4Byte: boolean;
  dexChecksumsUpdated: boolean;
  peChecksumUpdated: boolean;
  manifestDigestsUpdated: boolean;
  repackedSize: number;
  summary: string;
}

export interface ScannedBinaryFile {
  id: string;
  name: string;
  relativePath: string;
  size: number;
  isPE: boolean;
  isAPK?: boolean;
  isDEX?: boolean;
  architecture: string; // e.g. "Android APK (DEX + ARM64)", "Dalvik DEX 039", "PE32+ (x86_64)"
  overallEntropy: number; // 0.00 - 8.00 bits/byte
  packerDetected: string | null;
  obfuscatedHitsCount: number;
  sections: PESectionInfo[];
  originalBuffer: Uint8Array;
  workingBuffer: Uint8Array;
  repackedBuffer?: Uint8Array; // Final repacked output (e.g. zipaligned APK with updated META-INF manifest)
  repackInfo?: RepackReportInfo;
  originalSha256: string;
  workingSha256: string;
  findings: TelemetryFinding[];
  isModified: boolean;
}

/**
 * Computes Shannon entropy (0.00 to 8.00 bits per byte) for a byte slice.
 */
export function calculateShannonEntropy(buffer: Uint8Array): number {
  if (buffer.length === 0) return 0;
  const counts = new Uint32Array(256);
  const len = buffer.length;
  for (let i = 0; i < len; i++) {
    counts[buffer[i]]++;
  }
  let entropy = 0;
  for (let i = 0; i < 256; i++) {
    const c = counts[i];
    if (c > 0) {
      const p = c / len;
      entropy -= p * Math.log2(p);
    }
  }
  return Math.round(entropy * 100) / 100;
}

/**
 * Standard IEEE 802.3 CRC-32 calculation for ZIP / APK container integrity.
 */
const CRC32_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[i] = c >>> 0;
  }
  return table;
})();

export function computeCrc32(buffer: Uint8Array): number {
  let crc = 0xffffffff;
  for (let i = 0; i < buffer.length; i++) {
    crc = CRC32_TABLE[(crc ^ buffer[i]) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

/**
 * Computes Adler-32 checksum used by Android Dalvik/ART DEX headers (bytes 0x08..0x0B, computed over 0x0C..end).
 */
export function computeAdler32(buffer: Uint8Array, startOffset = 12): number {
  const MOD_ADLER = 65521;
  let a = 1;
  let b = 0;
  for (let i = startOffset; i < buffer.length; i++) {
    a = (a + buffer[i]) % MOD_ADLER;
    b = (b + a) % MOD_ADLER;
  }
  return ((b << 16) | a) >>> 0;
}

/**
 * Recomputes the DEX SHA-1 signature (offset 12..31, computed over 32..end) and
 * Adler-32 checksum (offset 8..11, computed over 12..end) in-place on a DEX byte slice.
 */
export async function updateDexHeaderChecksumsInPlace(dexSlice: Uint8Array): Promise<boolean> {
  if (
    dexSlice.length < 0x70 ||
    dexSlice[0] !== 0x64 || // 'd'
    dexSlice[1] !== 0x65 || // 'e'
    dexSlice[2] !== 0x78 || // 'x'
    dexSlice[3] !== 0x0a    // '\n'
  ) {
    return false;
  }

  try {
    const payloadAfterSig = new Uint8Array(dexSlice.length - 32);
    payloadAfterSig.set(dexSlice.subarray(32));
    const sha1Buf = await crypto.subtle.digest('SHA-1', payloadAfterSig.buffer);
    const sha1Bytes = new Uint8Array(sha1Buf);
    if (sha1Bytes.length === 20) {
      dexSlice.set(sha1Bytes, 12);
    }
  } catch {
    // Fallback if SHA-1 digest unavailable
  }

  const adler = computeAdler32(dexSlice, 12);
  const view = new DataView(dexSlice.buffer, dexSlice.byteOffset, dexSlice.byteLength);
  view.setUint32(8, adler, true);
  return true;
}

/**
 * Computes and updates the Windows PE OptionalHeader.CheckSum (at peOffset + 24 + 64)
 * using the standard 16-bit folding algorithm (ImageHlp / MapFileAndCheckSum).
 */
export function updatePEHeaderChecksumInPlace(peBuffer: Uint8Array): boolean {
  if (peBuffer.length < 0x100 || peBuffer[0] !== 0x4d || peBuffer[1] !== 0x5a) {
    return false;
  }
  const view = new DataView(peBuffer.buffer, peBuffer.byteOffset, peBuffer.byteLength);
  const peOffset = view.getUint32(0x3c, true);
  if (peOffset + 24 + 68 > peBuffer.length) return false;
  if (
    peBuffer[peOffset] !== 0x50 ||
    peBuffer[peOffset + 1] !== 0x45 ||
    peBuffer[peOffset + 2] !== 0x00 ||
    peBuffer[peOffset + 3] !== 0x00
  ) {
    return false;
  }

  const checksumOffset = peOffset + 24 + 64;
  // Zero out existing CheckSum field before computing
  view.setUint32(checksumOffset, 0, true);

  let sum = 0;
  const wordCount = Math.floor(peBuffer.length / 2);
  for (let i = 0; i < wordCount; i++) {
    const byteIdx = i * 2;
    const word = view.getUint16(byteIdx, true);
    sum += word;
    sum = (sum & 0xffff) + (sum >>> 16);
  }
  if (peBuffer.length % 2 === 1) {
    sum += peBuffer[peBuffer.length - 1];
    sum = (sum & 0xffff) + (sum >>> 16);
  }
  sum = (sum & 0xffff) + (sum >>> 16);
  const finalChecksum = (sum + peBuffer.length) >>> 0;
  view.setUint32(checksumOffset, finalChecksum, true);
  return true;
}

/**
 * Computes SHA-256 hex digest of a Uint8Array buffer using Web Crypto API.
 */
export async function computeSha256(buffer: Uint8Array): Promise<string> {
  try {
    const copy = new Uint8Array(buffer.byteLength);
    copy.set(buffer);
    const hashBuffer = await crypto.subtle.digest('SHA-256', copy.buffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
  } catch {
    let h1 = 0xdeadbeef ^ buffer.length;
    let h2 = 0x41c6ce57 ^ buffer.length;
    for (let i = 0; i < buffer.length; i++) {
      const ch = buffer[i];
      h1 = Math.imul(h1 ^ ch, 2654435761);
      h2 = Math.imul(h2 ^ ch, 1597334677);
    }
    h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
    h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
    return (
      (h1 >>> 0).toString(16).padStart(8, '0') +
      (h2 >>> 0).toString(16).padStart(8, '0')
    ).repeat(4);
  }
}

/**
 * Computes Base64-encoded SHA-256 digest of a byte slice (used for APK META-INF/MANIFEST.MF).
 */
async function computeSha256Base64(buffer: Uint8Array): Promise<string> {
  try {
    const copy = new Uint8Array(buffer.byteLength);
    copy.set(buffer);
    const hashBuffer = await crypto.subtle.digest('SHA-256', copy.buffer);
    const bytes = new Uint8Array(hashBuffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  } catch {
    return btoa('nullroute-offline-sha256-digest');
  }
}

/**
 * Decompresses raw DEFLATE bytes in browser memory using DecompressionStream('deflate-raw').
 */
async function inflateRawBytes(compressed: Uint8Array): Promise<Uint8Array | null> {
  try {
    if (typeof DecompressionStream === 'undefined') return null;
    const ds = new DecompressionStream('deflate-raw');
    const writer = ds.writable.getWriter();
    const copy = new Uint8Array(compressed.byteLength);
    copy.set(compressed);
    writer.write(copy);
    writer.close();

    const reader = ds.readable.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) {
        chunks.push(value);
        total += value.byteLength;
        if (total > 48 * 1024 * 1024) break;
      }
    }
    const out = new Uint8Array(total);
    let pos = 0;
    for (const c of chunks) {
      out.set(c, pos);
      pos += c.byteLength;
    }
    return out;
  } catch {
    return null;
  }
}

export interface ZipEntryRecord {
  name: string;
  data: Uint8Array;
}

/**
 * Builds a 4-byte `zipalign`-compliant, uncompressed (STORE method = 0) ZIP / APK archive
 * in memory. For every entry, pads the Local File Header's `extraField` by `0..3` bytes so
 * that the entry's raw data payload begins on an exact 4-byte boundary (`dataOffset % 4 === 0`).
 */
export function buildStoreZipArchive(entries: ZipEntryRecord[], zipAlign4Byte = true): Uint8Array {
  const localParts: Uint8Array[] = [];
  const centralParts: Uint8Array[] = [];
  let currentOffset = 0;

  for (const entry of entries) {
    const nameBytes = new TextEncoder().encode(entry.name);
    const data = entry.data;
    const crc = computeCrc32(data);

    // Calculate extra field padding needed so (currentOffset + 30 + nameBytes.length + extraLen) % 4 === 0
    const unpaddedDataOffset = currentOffset + 30 + nameBytes.length;
    const alignPad = zipAlign4Byte ? (4 - (unpaddedDataOffset % 4)) % 4 : 0;

    // Local File Header (30 bytes + nameLength + alignPad)
    const lfh = new Uint8Array(30 + nameBytes.length + alignPad);
    const lfhView = new DataView(lfh.buffer);
    lfhView.setUint32(0, 0x04034b50, true); // PK\x03\x04
    lfhView.setUint16(4, 20, true); // Version needed
    lfhView.setUint16(6, 0, true); // Flags
    lfhView.setUint16(8, 0, true); // Compression method: 0 (STORE)
    lfhView.setUint16(10, 0x4800, true); // Mod time
    lfhView.setUint16(12, 0x554e, true); // Mod date
    lfhView.setUint32(14, crc, true); // CRC-32
    lfhView.setUint32(18, data.byteLength, true); // Compressed size
    lfhView.setUint32(22, data.byteLength, true); // Uncompressed size
    lfhView.setUint16(26, nameBytes.length, true); // File name length
    lfhView.setUint16(28, alignPad, true); // Extra field length (zipalign padding)
    lfh.set(nameBytes, 30);

    // Central Directory File Header (46 bytes + nameLength)
    const cdh = new Uint8Array(46 + nameBytes.length);
    const cdhView = new DataView(cdh.buffer);
    cdhView.setUint32(0, 0x02014b50, true); // PK\x01\x02
    cdhView.setUint16(4, 20, true);
    cdhView.setUint16(6, 20, true);
    cdhView.setUint16(8, 0, true);
    cdhView.setUint16(10, 0, true); // STORE
    cdhView.setUint16(12, 0x4800, true);
    cdhView.setUint16(14, 0x554e, true);
    cdhView.setUint32(16, crc, true); // CRC-32
    cdhView.setUint32(20, data.byteLength, true);
    cdhView.setUint32(24, data.byteLength, true);
    cdhView.setUint16(28, nameBytes.length, true);
    cdhView.setUint16(30, 0, true);
    cdhView.setUint16(32, 0, true);
    cdhView.setUint16(34, 0, true);
    cdhView.setUint16(36, 0, true);
    cdhView.setUint32(38, 0, true);
    cdhView.setUint32(42, currentOffset, true); // Relative offset of local header
    cdh.set(nameBytes, 46);

    localParts.push(lfh, data);
    centralParts.push(cdh);
    currentOffset += lfh.byteLength + data.byteLength;
  }

  const centralDirOffset = currentOffset;
  let centralDirSize = 0;
  for (const c of centralParts) centralDirSize += c.byteLength;

  // End of Central Directory Record (22 bytes)
  const eocd = new Uint8Array(22);
  const eocdView = new DataView(eocd.buffer);
  eocdView.setUint32(0, 0x06054b50, true); // PK\x05\x06
  eocdView.setUint16(4, 0, true);
  eocdView.setUint16(6, 0, true);
  eocdView.setUint16(8, entries.length, true);
  eocdView.setUint16(10, entries.length, true);
  eocdView.setUint32(12, centralDirSize, true);
  eocdView.setUint32(16, centralDirOffset, true);
  eocdView.setUint16(20, 0, true);

  const totalSize = centralDirOffset + centralDirSize + 22;
  const finalBuf = new Uint8Array(totalSize);
  let pos = 0;
  for (const p of localParts) {
    finalBuf.set(p, pos);
    pos += p.byteLength;
  }
  for (const c of centralParts) {
    finalBuf.set(c, pos);
    pos += c.byteLength;
  }
  finalBuf.set(eocd, pos);
  return finalBuf;
}

/**
 * Automatically repacks a patched Android APK buffer:
 * 1. Extracts all APK entries and updates DEX SHA-1 & Adler-32 headers on all .dex files.
 * 2. Computes fresh SHA-256 Base64 digests for every entry and generates/updates
 *    `META-INF/MANIFEST.MF` and `META-INF/NULLROUTE.SF`.
 * 3. Repacks the entire APK with strict 4-byte `zipalign` alignment and updated CRC-32s.
 */
export async function repackApkWithManifestAndZipalign(
  apkBuffer: Uint8Array,
  sections: PESectionInfo[]
): Promise<{ repackedBuffer: Uint8Array; manifestEntriesUpdated: number }> {
  const entries: ZipEntryRecord[] = [];
  const manifestLines: string[] = [
    'Manifest-Version: 1.0',
    'Created-By: NullRoute Offline APK Repacker (4-Byte ZipAligned)',
    '',
  ];

  let manifestEntriesUpdated = 0;

  for (const sec of sections) {
    // Skip old signature block files so we can write fresh updated ones
    if (sec.name.startsWith('META-INF/')) continue;

    const slice = new Uint8Array(
      Math.max(0, Math.min(sec.rawSize, apkBuffer.length - sec.rawAddress))
    );
    slice.set(
      apkBuffer.subarray(
        Math.min(sec.rawAddress, apkBuffer.length),
        Math.min(sec.rawAddress + sec.rawSize, apkBuffer.length)
      )
    );

    if (sec.isDexEntry || sec.name.endsWith('.dex')) {
      await updateDexHeaderChecksumsInPlace(slice);
    }

    const digestB64 = await computeSha256Base64(slice);
    manifestLines.push(`Name: ${sec.name}`);
    manifestLines.push(`SHA-256-Digest: ${digestB64}`);
    manifestLines.push('');
    manifestEntriesUpdated++;

    entries.push({ name: sec.name, data: slice });
  }

  const manifestText = manifestLines.join('\r\n');
  const manifestBytes = new TextEncoder().encode(manifestText);
  const manifestFullDigest = await computeSha256Base64(manifestBytes);

  const sfLines = [
    'Signature-Version: 1.0',
    'Created-By: NullRoute Offline APK Repacker',
    `SHA-256-Digest-Manifest: ${manifestFullDigest}`,
    '',
  ];
  const sfBytes = new TextEncoder().encode(sfLines.join('\r\n'));

  entries.push({ name: 'META-INF/MANIFEST.MF', data: manifestBytes });
  entries.push({ name: 'META-INF/NULLROUTE.SF', data: sfBytes });

  const repackedBuffer = buildStoreZipArchive(entries, true);
  return { repackedBuffer, manifestEntriesUpdated };
}

/**
 * If an uploaded buffer is a ZIP / Android APK, normalizes all entries into a 4-byte zipaligned
 * STORE archive in memory so that classes.dex, AndroidManifest.xml, resources.arsc, and lib/*.so
 * are directly addressable in the hex viewer and patchable in-place.
 */
async function normalizeApkOrZipBuffer(rawBuffer: Uint8Array): Promise<Uint8Array> {
  if (
    rawBuffer.length < 30 ||
    rawBuffer[0] !== 0x50 ||
    rawBuffer[1] !== 0x4b ||
    rawBuffer[2] !== 0x03 ||
    rawBuffer[3] !== 0x04
  ) {
    return rawBuffer;
  }

  const view = new DataView(rawBuffer.buffer, rawBuffer.byteOffset, rawBuffer.byteLength);
  let eocdOffset = -1;
  const minSearch = Math.max(0, rawBuffer.length - 65557);
  for (let i = rawBuffer.length - 22; i >= minSearch; i--) {
    if (view.getUint32(i, true) === 0x06054b50) {
      eocdOffset = i;
      break;
    }
  }
  if (eocdOffset === -1) return rawBuffer;

  const numEntries = view.getUint16(eocdOffset + 10, true);
  const cdOffset = view.getUint32(eocdOffset + 16, true);
  if (cdOffset >= rawBuffer.length) return rawBuffer;

  let hasDeflatedScannable = false;
  let ptr = cdOffset;
  const parsedEntries: {
    name: string;
    method: number;
    compSize: number;
    uncompSize: number;
    localHeaderOffset: number;
  }[] = [];

  for (let i = 0; i < Math.min(numEntries, 400); i++) {
    if (ptr + 46 > rawBuffer.length || view.getUint32(ptr, true) !== 0x02014b50) break;
    const method = view.getUint16(ptr + 10, true);
    const compSize = view.getUint32(ptr + 20, true);
    const uncompSize = view.getUint32(ptr + 24, true);
    const nameLen = view.getUint16(ptr + 28, true);
    const extraLen = view.getUint16(ptr + 30, true);
    const commentLen = view.getUint16(ptr + 32, true);
    const localHeaderOffset = view.getUint32(ptr + 42, true);

    if (ptr + 46 + nameLen > rawBuffer.length) break;
    const name = new TextDecoder().decode(rawBuffer.subarray(ptr + 46, ptr + 46 + nameLen));
    if (method === 8) {
      hasDeflatedScannable = true;
    }
    parsedEntries.push({ name, method, compSize, uncompSize, localHeaderOffset });
    ptr += 46 + nameLen + extraLen + commentLen;
  }

  if (!hasDeflatedScannable) {
    return rawBuffer;
  }

  const rebuiltEntries: ZipEntryRecord[] = [];
  for (const item of parsedEntries) {
    const lfh = item.localHeaderOffset;
    if (lfh + 30 > rawBuffer.length || view.getUint32(lfh, true) !== 0x04034b50) continue;
    const lfhNameLen = view.getUint16(lfh + 26, true);
    const lfhExtraLen = view.getUint16(lfh + 28, true);
    const dataStart = lfh + 30 + lfhNameLen + lfhExtraLen;
    if (dataStart + item.compSize > rawBuffer.length) continue;

    const compSlice = rawBuffer.subarray(dataStart, dataStart + item.compSize);
    if (item.method === 0) {
      rebuiltEntries.push({ name: item.name, data: compSlice });
    } else if (item.method === 8) {
      const inflated = await inflateRawBytes(compSlice);
      if (inflated) {
        rebuiltEntries.push({ name: item.name, data: inflated });
      } else {
        rebuiltEntries.push({ name: item.name, data: compSlice });
      }
    }
  }

  if (rebuiltEntries.length === 0) return rawBuffer;
  return buildStoreZipArchive(rebuiltEntries, true);
}

const KNOWN_PACKER_SECTIONS: Record<string, string> = {
  UPX0: 'UPX Executable Packer',
  UPX1: 'UPX Executable Packer',
  UPX2: 'UPX Executable Packer',
  '.vmp0': 'VMProtect Virtualized Binary',
  '.vmp1': 'VMProtect Virtualized Binary',
  '.themida': 'Themida / WinLicense Protector',
  '.aspack': 'ASPack Compressor',
  '.adata': 'ASPack Compressor',
  '.mpress1': 'MPRESS Packer',
  '.mpress2': 'MPRESS Packer',
  'libjiagu.so': 'Qihoo 360 Jiagu APK Packer',
  'libsecmain.so': 'Bangcle / SecNeo APK Protector',
  'libDexHelper.so': 'SecNeo DEX Protector',
  'libexec.so': 'Tencent Legu APK Protector',
};

/**
 * Parses binary headers for Windows PE (.exe/.dll), Android APK (ZIP), Dalvik DEX (.dex), and ELF (.so).
 */
export function parseBinaryHeaders(buffer: Uint8Array): {
  isPE: boolean;
  isAPK: boolean;
  isDEX: boolean;
  architecture: string;
  sections: PESectionInfo[];
  packerDetected: string | null;
} {
  if (buffer.length < 32) {
    return {
      isPE: false,
      isAPK: false,
      isDEX: false,
      architecture: 'Raw Binary / Data',
      sections: [],
      packerDetected: null,
    };
  }

  // 1. Check Android Dalvik Executable (DEX) Magic: 'dex\n035\0' or 'dex\n039\0'
  if (
    buffer[0] === 0x64 &&
    buffer[1] === 0x65 &&
    buffer[2] === 0x78 &&
    buffer[3] === 0x0a
  ) {
    const ver = String.fromCharCode(buffer[4], buffer[5], buffer[6]);
    const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    const stringIdsSize = buffer.length >= 0x40 ? view.getUint32(0x38, true) : 0;
    const stringIdsOff = buffer.length >= 0x40 ? view.getUint32(0x3c, true) : 0x70;
    const dataSize = buffer.length >= 0x70 ? view.getUint32(0x68, true) : buffer.length - 0x70;
    const dataOff = buffer.length >= 0x70 ? view.getUint32(0x6c, true) : 0x70;

    const sections: PESectionInfo[] = [
      {
        name: 'dex.header',
        virtualAddress: 0,
        virtualSize: 0x70,
        rawAddress: 0,
        rawSize: Math.min(0x70, buffer.length),
        entropy: calculateShannonEntropy(buffer.subarray(0, Math.min(0x70, buffer.length))),
        isDexEntry: true,
      },
    ];

    if (stringIdsOff > 0 && stringIdsOff < buffer.length) {
      const poolStart = Math.min(dataOff || stringIdsOff, buffer.length);
      const poolSize = Math.min(dataSize || buffer.length - poolStart, buffer.length - poolStart);
      sections.push({
        name: 'dex.string_pool',
        virtualAddress: poolStart,
        virtualSize: poolSize,
        rawAddress: poolStart,
        rawSize: poolSize,
        entropy: calculateShannonEntropy(buffer.subarray(poolStart, poolStart + poolSize)),
        isDexEntry: true,
      });
    }

    return {
      isPE: false,
      isAPK: false,
      isDEX: true,
      architecture: `Dalvik DEX v${ver} (${stringIdsSize} strings)`,
      sections,
      packerDetected: null,
    };
  }

  // 2. Check Android APK / ZIP Container Magic: 'PK\x03\x04'
  if (
    buffer[0] === 0x50 &&
    buffer[1] === 0x4b &&
    buffer[2] === 0x03 &&
    buffer[3] === 0x04
  ) {
    const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    const sections: PESectionInfo[] = [];
    let packerDetected: string | null = null;
    let hasDex = false;
    let hasManifest = false;
    let nativeArch = '';

    let eocdOffset = -1;
    const minSearch = Math.max(0, buffer.length - 65557);
    for (let i = buffer.length - 22; i >= minSearch; i--) {
      if (view.getUint32(i, true) === 0x06054b50) {
        eocdOffset = i;
        break;
      }
    }

    if (eocdOffset !== -1) {
      const numEntries = view.getUint16(eocdOffset + 10, true);
      let cdPtr = view.getUint32(eocdOffset + 16, true);

      for (let i = 0; i < Math.min(numEntries, 250); i++) {
        if (cdPtr + 46 > buffer.length || view.getUint32(cdPtr, true) !== 0x02014b50) break;
        const compSize = view.getUint32(cdPtr + 20, true);
        const nameLen = view.getUint16(cdPtr + 28, true);
        const extraLen = view.getUint16(cdPtr + 30, true);
        const commentLen = view.getUint16(cdPtr + 32, true);
        const lfhOffset = view.getUint32(cdPtr + 42, true);

        if (cdPtr + 46 + nameLen > buffer.length) break;
        const entryName = new TextDecoder().decode(
          buffer.subarray(cdPtr + 46, cdPtr + 46 + nameLen)
        );

        if (lfhOffset + 30 <= buffer.length && view.getUint32(lfhOffset, true) === 0x04034b50) {
          const lfhNameLen = view.getUint16(lfhOffset + 26, true);
          const lfhExtraLen = view.getUint16(lfhOffset + 28, true);
          const dataAddress = lfhOffset + 30 + lfhNameLen + lfhExtraLen;
          const safeEnd = Math.min(dataAddress + compSize, buffer.length);
          const slice = buffer.subarray(Math.min(dataAddress, buffer.length), safeEnd);
          const entropy = calculateShannonEntropy(slice);

          const baseName = entryName.split('/').pop() || entryName;
          if (KNOWN_PACKER_SECTIONS[baseName]) {
            packerDetected = KNOWN_PACKER_SECTIONS[baseName];
          }
          if (entryName.endsWith('.dex')) hasDex = true;
          if (entryName === 'AndroidManifest.xml') hasManifest = true;
          if (entryName.includes('arm64-v8a')) nativeArch = 'ARM64';
          else if (entryName.includes('armeabi-v7a') && !nativeArch) nativeArch = 'ARMv7';
          else if (entryName.includes('x86_64') && !nativeArch) nativeArch = 'x86_64';

          const isDexEntry =
            slice.length >= 0x70 &&
            slice[0] === 0x64 &&
            slice[1] === 0x65 &&
            slice[2] === 0x78 &&
            slice[3] === 0x0a;

          sections.push({
            name: entryName,
            virtualAddress: dataAddress,
            virtualSize: compSize,
            rawAddress: dataAddress,
            rawSize: compSize,
            entropy,
            zipLocalHeaderOffset: lfhOffset,
            zipCentralHeaderOffset: cdPtr,
            isDexEntry,
          });
        }

        cdPtr += 46 + nameLen + extraLen + commentLen;
      }
    }

    const isAndroidApk = hasDex || hasManifest || sections.some((s) => s.name.endsWith('.arsc'));
    const archLabel = isAndroidApk
      ? `Android APK (${hasDex ? 'DEX' : 'Package'}${nativeArch ? ` + ${nativeArch}` : ''})`
      : 'ZIP Package Container';

    return {
      isPE: false,
      isAPK: true,
      isDEX: false,
      architecture: archLabel,
      sections,
      packerDetected,
    };
  }

  // 3. Check ELF (.so / Linux / Android NDK) Magic: 0x7F 'E' 'L' 'F'
  if (
    buffer[0] === 0x7f &&
    buffer[1] === 0x45 &&
    buffer[2] === 0x4c &&
    buffer[3] === 0x46
  ) {
    const is64 = buffer[4] === 2;
    const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    const machine = view.getUint16(0x12, true);
    let archName = is64 ? 'ELF 64-bit' : 'ELF 32-bit';
    if (machine === 0xb7) archName = 'ELF64 (Android ARM64 .so)';
    else if (machine === 0x28) archName = 'ELF32 (Android ARMv7 .so)';
    else if (machine === 0x3e) archName = 'ELF64 (x86_64 .so)';

    return {
      isPE: false,
      isAPK: false,
      isDEX: false,
      architecture: archName,
      sections: [],
      packerDetected: null,
    };
  }

  // 4. Check Windows PE ('MZ' + 'PE\0\0')
  if (buffer[0] !== 0x4d || buffer[1] !== 0x5a) {
    return {
      isPE: false,
      isAPK: false,
      isDEX: false,
      architecture: 'Binary / Resource Stream',
      sections: [],
      packerDetected: null,
    };
  }

  const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  const peOffset = view.getUint32(0x3c, true);
  if (peOffset + 24 >= buffer.length) {
    return {
      isPE: false,
      isAPK: false,
      isDEX: false,
      architecture: 'DOS / MZ Binary',
      sections: [],
      packerDetected: null,
    };
  }

  if (
    buffer[peOffset] !== 0x50 ||
    buffer[peOffset + 1] !== 0x45 ||
    buffer[peOffset + 2] !== 0x00 ||
    buffer[peOffset + 3] !== 0x00
  ) {
    return {
      isPE: false,
      isAPK: false,
      isDEX: false,
      architecture: 'DOS / MZ Binary',
      sections: [],
      packerDetected: null,
    };
  }

  const machine = view.getUint16(peOffset + 4, true);
  const numSections = view.getUint16(peOffset + 6, true);
  const sizeOfOptionalHeader = view.getUint16(peOffset + 20, true);

  let architecture = 'PE Executable';
  if (machine === 0x8664) architecture = 'PE32+ (x86_64)';
  else if (machine === 0x014c) architecture = 'PE32 (x86)';
  else if (machine === 0xaa64) architecture = 'PE32+ (ARM64)';

  const sectionTableOffset = peOffset + 24 + sizeOfOptionalHeader;
  const sections: PESectionInfo[] = [];
  let packerDetected: string | null = null;

  for (let i = 0; i < Math.min(numSections, 32); i++) {
    const secOffset = sectionTableOffset + i * 40;
    if (secOffset + 40 > buffer.length) break;

    let name = '';
    for (let j = 0; j < 8; j++) {
      const ch = buffer[secOffset + j];
      if (ch === 0) break;
      if (ch >= 32 && ch <= 126) name += String.fromCharCode(ch);
    }

    const virtualSize = view.getUint32(secOffset + 8, true);
    const virtualAddress = view.getUint32(secOffset + 12, true);
    const rawSize = view.getUint32(secOffset + 16, true);
    const rawAddress = view.getUint32(secOffset + 20, true);

    const safeStart = Math.min(rawAddress, buffer.length);
    const safeEnd = Math.min(rawAddress + rawSize, buffer.length);
    const secSlice = buffer.subarray(safeStart, safeEnd);
    const entropy = calculateShannonEntropy(secSlice);

    const cleanName = name || `.sec${i}`;
    if (KNOWN_PACKER_SECTIONS[cleanName]) {
      packerDetected = KNOWN_PACKER_SECTIONS[cleanName];
    } else if (entropy >= 7.25 && !packerDetected) {
      packerDetected = `High-Entropy Packed Section (${cleanName}: ${entropy.toFixed(2)} b/B)`;
    }

    sections.push({
      name: cleanName,
      virtualAddress,
      virtualSize,
      rawAddress,
      rawSize,
      entropy,
    });
  }

  return { isPE: true, isAPK: false, isDEX: false, architecture, sections, packerDetected };
}

function resolveSectionForOffset(offset: number, sections: PESectionInfo[]): PESectionInfo | null {
  for (const sec of sections) {
    if (offset >= sec.rawAddress && offset < sec.rawAddress + sec.rawSize) {
      return sec;
    }
  }
  return null;
}

interface ExtractedRawString {
  text: string;
  encodedPreview?: string;
  offset: number;
  byteLength: number;
  encoding: StringEncoding;
  obfuscationDetail?: string;
  xorKey?: number;
}

function decodeRot13(input: string): string {
  return input.replace(/[a-zA-Z]/g, (c) => {
    const base = c <= 'Z' ? 65 : 97;
    return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
  });
}

function encodeRot13(input: string): string {
  return decodeRot13(input);
}

/**
 * Extracts printable ASCII, DEX MUTF-8, UTF-16LE (PE & Android AXML), and Obfuscated strings
 * (Single-Byte XOR-8, Base64-encoded URLs, Reversed strings, ROT13 strings, and Hex-encoded strings).
 */
function extractCandidateStrings(
  buffer: Uint8Array,
  minChars = 7,
  scanObfuscated = true
): ExtractedRawString[] {
  const results: ExtractedRawString[] = [];
  const len = buffer.length;

  const inspectAsciiCandidate = (rawStr: string, startOffset: number) => {
    const charLen = rawStr.length;

    if (rawStr.includes('.')) {
      results.push({
        text: rawStr,
        offset: startOffset,
        byteLength: charLen,
        encoding: 'ASCII',
      });
    }

    if (!scanObfuscated) return;

    if (rawStr.includes('//:sptth') || rawStr.includes('//:ptth')) {
      const reversed = rawStr.split('').reverse().join('');
      if (reversed.includes('.')) {
        results.push({
          text: reversed,
          encodedPreview: rawStr,
          offset: startOffset,
          byteLength: charLen,
          encoding: 'Reversed',
          obfuscationDetail: 'Reversed Byte Order',
        });
      }
    }

    const lowerRaw = rawStr.toLowerCase();
    if (lowerRaw.includes('uggcf://') || lowerRaw.includes('uggc://')) {
      const decodedRot = decodeRot13(rawStr);
      if (decodedRot.includes('.')) {
        results.push({
          text: decodedRot,
          encodedPreview: rawStr,
          offset: startOffset,
          byteLength: charLen,
          encoding: 'ROT13',
          obfuscationDetail: 'ROT13 Substitution Cipher',
        });
      }
    }

    const b64Regex = /(?:aHR0cHM6Ly|aHR0cDov|d3NzOi8v)[A-Za-z0-9+/]{8,}={0,2}/g;
    let b64Match: RegExpExecArray | null;
    while ((b64Match = b64Regex.exec(rawStr)) !== null) {
      const b64Token = b64Match[0];
      try {
        const decoded = atob(b64Token);
        if (decoded.length >= 10 && decoded.includes('.') && /^[\x20-\x7e]+$/.test(decoded)) {
          results.push({
            text: decoded,
            encodedPreview: b64Token,
            offset: startOffset + b64Match.index,
            byteLength: b64Token.length,
            encoding: 'Base64',
            obfuscationDetail: 'Base64 Encoded (RFC 4648)',
          });
        }
      } catch {
        // Ignore invalid base64 padding
      }
    }

    const hexUrlRegex = /(?:68747470733a2f2f|687474703a2f2f)[0-9a-fA-F]{14,}/gi;
    let hexMatch: RegExpExecArray | null;
    while ((hexMatch = hexUrlRegex.exec(rawStr)) !== null) {
      const hexToken = hexMatch[0];
      const evenLen = hexToken.length - (hexToken.length % 2);
      let decodedHex = '';
      for (let h = 0; h < evenLen; h += 2) {
        const byteVal = parseInt(hexToken.slice(h, h + 2), 16);
        if (byteVal < 0x21 || byteVal > 0x7e) {
          break;
        }
        decodedHex += String.fromCharCode(byteVal);
      }
      if (decodedHex.length >= 10 && decodedHex.includes('.')) {
        results.push({
          text: decodedHex,
          encodedPreview: hexToken.slice(0, decodedHex.length * 2),
          offset: startOffset + hexMatch.index,
          byteLength: decodedHex.length * 2,
          encoding: 'Hex-Encoded',
          obfuscationDetail: 'Hex-Encoded ASCII Stream',
        });
      }
    }
  };

  let start = -1;
  for (let i = 0; i < len; i++) {
    const b = buffer[i];
    if (b >= 0x21 && b <= 0x7e) {
      if (start === -1) start = i;
    } else {
      if (start !== -1) {
        const charLen = i - start;
        if (charLen >= minChars && charLen <= 512) {
          let str = '';
          for (let k = start; k < i; k++) {
            str += String.fromCharCode(buffer[k]);
          }
          inspectAsciiCandidate(str, start);
        }
        start = -1;
      }
    }
  }
  if (start !== -1 && len - start >= minChars && len - start <= 512) {
    let str = '';
    for (let k = start; k < len; k++) str += String.fromCharCode(buffer[k]);
    inspectAsciiCandidate(str, start);
  }

  for (let parity = 0; parity < 2; parity++) {
    let wStart = -1;
    let wChars = 0;
    let hasDot = false;

    for (let i = parity; i + 1 < len; i += 2) {
      const lo = buffer[i];
      const hi = buffer[i + 1];
      if (hi === 0x00 && lo >= 0x21 && lo <= 0x7e) {
        if (wStart === -1) {
          wStart = i;
          wChars = 0;
          hasDot = false;
        }
        wChars++;
        if (lo === 0x2e) hasDot = true;
      } else {
        if (wStart !== -1) {
          if (wChars >= minChars && wChars <= 512 && hasDot) {
            let str = '';
            for (let k = 0; k < wChars; k++) {
              str += String.fromCharCode(buffer[wStart + k * 2]);
            }
            results.push({
              text: str,
              offset: wStart,
              byteLength: wChars * 2,
              encoding: 'UTF-16LE',
            });
          }
          wStart = -1;
        }
      }
    }
  }

  if (scanObfuscated && len >= 16) {
    for (let i = 0; i < len - 12; i++) {
      if (buffer[i + 1] !== buffer[i + 2]) continue;

      const candidateKey = buffer[i] ^ 0x68;
      if (candidateKey === 0x00 || candidateKey === 0xff) continue;

      if (
        (buffer[i + 1] ^ candidateKey) !== 0x74 ||
        (buffer[i + 3] ^ candidateKey) !== 0x70
      ) {
        continue;
      }

      const b4 = buffer[i + 4] ^ candidateKey;
      let isHttps = false;
      let isHttp = false;

      if (
        b4 === 0x73 &&
        (buffer[i + 5] ^ candidateKey) === 0x3a &&
        (buffer[i + 6] ^ candidateKey) === 0x2f &&
        (buffer[i + 7] ^ candidateKey) === 0x2f
      ) {
        isHttps = true;
      } else if (
        b4 === 0x3a &&
        (buffer[i + 5] ^ candidateKey) === 0x2f &&
        (buffer[i + 6] ^ candidateKey) === 0x2f
      ) {
        isHttp = true;
      }

      if (!isHttps && !isHttp) continue;

      let decodedXor = '';
      let hexPreview = '';
      let k = i;
      while (k < len && k - i < 256) {
        const decByte = buffer[k] ^ candidateKey;
        if (decByte < 0x21 || decByte > 0x7e) break;
        decodedXor += String.fromCharCode(decByte);
        if (k - i < 16) {
          hexPreview += buffer[k].toString(16).toUpperCase().padStart(2, '0') + ' ';
        }
        k++;
      }

      if (decodedXor.length >= 12 && decodedXor.includes('.')) {
        const keyHex = `0x${candidateKey.toString(16).toUpperCase().padStart(2, '0')}`;
        results.push({
          text: decodedXor,
          encodedPreview: `XOR(${keyHex}): ${hexPreview.trim()}…`,
          offset: i,
          byteLength: decodedXor.length,
          encoding: 'XOR-8',
          obfuscationDetail: `Single-Byte XOR Key ${keyHex}`,
          xorKey: candidateKey,
        });
        i = k - 1;
      }
    }
  }

  return results;
}

const URL_OR_DOMAIN_REGEX =
  /(?:https?:\/\/|wss?:\/\/)?([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+)(?:\/[^\s"'<>\\`\x00]*)?/g;

const VALID_TLD_SET = new Set([
  'io',
  'com',
  'net',
  'org',
  'ms',
  'ai',
  'co',
  'app',
  'dev',
  'cloud',
  'gg',
  'me',
  'tv',
  'us',
  'eu',
  'de',
  'uk',
  'cn',
  'ru',
  'info',
  'biz',
]);

function matchDomainAgainstSignatures(
  domain: string,
  signatures: TelemetrySignature[],
  enableHeuristics: boolean
): {
  matched: boolean;
  vendor: string;
  category: TelemetryCategory;
  severity: SeverityLevel;
  description: string;
} | null {
  const lower = domain.toLowerCase();

  if (SAFE_DOMAIN_ALLOWLIST.has(lower)) {
    return null;
  }

  const parts = lower.split('.');
  if (parts.length < 2) return null;
  const tld = parts[parts.length - 1];
  if (!VALID_TLD_SET.has(tld)) return null;

  if (
    lower.endsWith('.dll') ||
    lower.endsWith('.exe') ||
    lower.endsWith('.sys') ||
    lower.endsWith('.pdb') ||
    lower.endsWith('.xml') ||
    lower.endsWith('.json') ||
    lower.endsWith('.dex') ||
    lower.endsWith('.apk') ||
    lower.endsWith('.so')
  ) {
    return null;
  }

  for (const sig of signatures) {
    const pat = sig.domainPattern.toLowerCase();
    if (lower === pat || lower.endsWith('.' + pat)) {
      return {
        matched: true,
        vendor: sig.vendor,
        category: sig.category,
        severity: sig.severity,
        description: sig.description,
      };
    }
  }

  if (enableHeuristics) {
    for (const kw of HEURISTIC_SUBDOMAIN_KEYWORDS) {
      const cleanKw = kw.trim();
      if (
        lower.startsWith(cleanKw + '.') ||
        lower.includes('.' + cleanKw + '.') ||
        lower.startsWith(cleanKw + '-') ||
        lower.includes('-' + cleanKw + '.')
      ) {
        return {
          matched: true,
          vendor: `Heuristic Match (${cleanKw}.*)`,
          category: 'Heuristic Subdomain',
          severity: 'Medium',
          description: `Subdomain matches known telemetry/ingestion pattern "${cleanKw}".`,
        };
      }
    }
  }

  return null;
}

/**
 * Scans a binary file buffer (.exe, .dll, .apk, .dex, .so, .arsc) for plaintext and obfuscated
 * telemetry domains and URLs. Automatically decompresses DEFLATE entries inside Android APKs.
 */
export async function scanBinaryBuffer(
  fileId: string,
  fileName: string,
  relativePath: string,
  rawInputBuffer: Uint8Array,
  customSignatures: TelemetrySignature[] = [],
  enableHeuristics = true
): Promise<ScannedBinaryFile> {
  const normalized = await normalizeApkOrZipBuffer(rawInputBuffer);

  const originalBuffer = new Uint8Array(normalized.byteLength);
  originalBuffer.set(normalized);

  const workingBuffer = new Uint8Array(normalized.byteLength);
  workingBuffer.set(normalized);

  const { isPE, isAPK, isDEX, architecture, sections, packerDetected } =
    parseBinaryHeaders(originalBuffer);
  const overallEntropy = calculateShannonEntropy(originalBuffer);
  const allSignatures = [...customSignatures, ...BUILTIN_TELEMETRY_SIGNATURES];

  const candidates = extractCandidateStrings(originalBuffer, 7, true);
  const findings: TelemetryFinding[] = [];
  const seenOffsets = new Set<string>();

  for (const cand of candidates) {
    URL_OR_DOMAIN_REGEX.lastIndex = 0;
    let match: RegExpExecArray | null;

    while ((match = URL_OR_DOMAIN_REGEX.exec(cand.text)) !== null) {
      const fullMatchedString = match[0];
      const domain = match[1];
      const charIndexInCandidate = match.index;

      const sigResult = matchDomainAgainstSignatures(domain, allSignatures, enableHeuristics);
      if (!sigResult) continue;

      let exactOffset = cand.offset;
      let exactByteLength = cand.byteLength;

      if (cand.encoding === 'ASCII' || cand.encoding === 'UTF-16LE') {
        const bytesPerChar = cand.encoding === 'UTF-16LE' ? 2 : 1;
        exactOffset = cand.offset + charIndexInCandidate * bytesPerChar;
        exactByteLength = fullMatchedString.length * bytesPerChar;
      } else if (cand.encoding === 'XOR-8' || cand.encoding === 'ROT13') {
        exactOffset = cand.offset + charIndexInCandidate;
        exactByteLength = fullMatchedString.length;
      }

      const matchedSection = resolveSectionForOffset(exactOffset, sections);
      const sectionName = matchedSection
        ? matchedSection.name
        : sections.length > 0
        ? '.rdata'
        : 'RAW';

      let finalEncoding: StringEncoding = cand.encoding;
      let finalObfDetail = cand.obfuscationDetail;
      if (
        cand.encoding === 'ASCII' &&
        (isDEX || matchedSection?.isDexEntry || sectionName.endsWith('.dex'))
      ) {
        finalEncoding = 'DEX-MUTF8';
        finalObfDetail = 'Dalvik/ART String Pool (ULEB128 Length-Prefixed)';
      }

      const key = `${exactOffset}:${exactByteLength}:${finalEncoding}`;
      if (seenOffsets.has(key)) continue;
      seenOffsets.add(key);

      const originalBytes = originalBuffer.slice(exactOffset, exactOffset + exactByteLength);

      findings.push({
        id: `${fileId}-0x${exactOffset.toString(16)}-${finalEncoding}`,
        fileId,
        fileName,
        filePath: relativePath || fileName,
        offset: exactOffset,
        byteLength: exactByteLength,
        encoding: finalEncoding,
        obfuscationDetail: finalObfDetail,
        xorKey: cand.xorKey,
        sectionName,
        rawString: fullMatchedString,
        encodedPreview: cand.encodedPreview,
        domain: domain.toLowerCase(),
        vendor: sigResult.vendor,
        category: sigResult.category,
        severity: sigResult.severity,
        description: sigResult.description,
        selected: true,
        patched: false,
        originalBytes,
      });
    }
  }

  findings.sort((a, b) => a.offset - b.offset);

  const obfuscatedHitsCount = findings.filter(
    (f) => f.encoding !== 'ASCII' && f.encoding !== 'UTF-16LE' && f.encoding !== 'DEX-MUTF8'
  ).length;

  const sha256 = await computeSha256(originalBuffer);

  return {
    id: fileId,
    name: fileName,
    relativePath: relativePath || fileName,
    size: originalBuffer.byteLength,
    isPE,
    isAPK,
    isDEX,
    architecture,
    overallEntropy,
    packerDetected,
    obfuscatedHitsCount,
    sections,
    originalBuffer,
    workingBuffer,
    originalSha256: sha256,
    workingSha256: sha256,
    findings,
    isModified: false,
  };
}

/**
 * Generates the exact-length replacement byte sequence for a finding based on the chosen strategy,
 * automatically preserving DEX MUTF-8 ULEB128 string length or obfuscation transforms.
 */
export function buildReplacementBytes(
  finding: TelemetryFinding,
  strategy: PatchStrategy
): Uint8Array {
  const out = new Uint8Array(finding.byteLength);

  if (finding.encoding === 'DEX-MUTF8') {
    const raw = finding.rawString;
    let base = 'https://0.0.0.0/';
    if (strategy === 'null_wipe') {
      base = '0.0.0.0/';
    } else if (raw.toLowerCase().startsWith('http://')) {
      base = 'http://0.0.0.0/';
    }
    const padded = base.padEnd(finding.byteLength, '0').slice(0, finding.byteLength);
    for (let i = 0; i < finding.byteLength; i++) {
      out[i] = padded.charCodeAt(i) & 0xff;
    }
    return out;
  }

  if (strategy === 'null_wipe') {
    if (finding.encoding === 'XOR-8' && finding.xorKey !== undefined) {
      out.fill(finding.xorKey & 0xff);
    }
    return out;
  }

  const raw = finding.rawString;
  let plainTarget = '0.0.0.0';

  if (strategy === 'loopback') {
    if (raw.toLowerCase().startsWith('https://')) {
      plainTarget = 'https://0.0.0.0';
    } else if (raw.toLowerCase().startsWith('http://')) {
      plainTarget = 'http://0.0.0.0';
    } else if (raw.toLowerCase().startsWith('wss://')) {
      plainTarget = 'wss://0.0.0.0';
    } else {
      plainTarget = '0.0.0.0';
    }
  } else if (strategy === 'nxdomain') {
    const domainIdx = raw.toLowerCase().indexOf(finding.domain.toLowerCase());
    if (domainIdx !== -1 && finding.domain.length >= 7) {
      const prefix = raw.slice(0, domainIdx);
      const neutralizedDomain = '0.0.0.0'.padEnd(finding.domain.length, '\x00');
      plainTarget = prefix + neutralizedDomain;
    } else {
      plainTarget = '0.0.0.0';
    }
  }

  if (finding.encoding === 'XOR-8' && finding.xorKey !== undefined) {
    const key = finding.xorKey & 0xff;
    out.fill(key);
    const writeLen = Math.min(plainTarget.length, finding.byteLength);
    for (let i = 0; i < writeLen; i++) {
      out[i] = (plainTarget.charCodeAt(i) & 0xff) ^ key;
    }
    return out;
  }

  if (finding.encoding === 'Base64') {
    const b64Loopback = btoa(plainTarget);
    const writeLen = Math.min(b64Loopback.length, finding.byteLength);
    for (let i = 0; i < writeLen; i++) {
      out[i] = b64Loopback.charCodeAt(i) & 0xff;
    }
    return out;
  }

  if (finding.encoding === 'Reversed') {
    const padded = plainTarget.padEnd(finding.byteLength, '/');
    const rev = padded.slice(0, finding.byteLength).split('').reverse().join('');
    for (let i = 0; i < finding.byteLength; i++) {
      out[i] = rev.charCodeAt(i) & 0xff;
    }
    return out;
  }

  if (finding.encoding === 'ROT13') {
    const rotTarget = encodeRot13(plainTarget);
    const writeLen = Math.min(rotTarget.length, finding.byteLength);
    for (let i = 0; i < writeLen; i++) {
      out[i] = rotTarget.charCodeAt(i) & 0xff;
    }
    return out;
  }

  if (finding.encoding === 'Hex-Encoded') {
    let hexTarget = '';
    for (let i = 0; i < plainTarget.length; i++) {
      hexTarget += plainTarget.charCodeAt(i).toString(16).padStart(2, '0');
    }
    hexTarget = hexTarget.padEnd(finding.byteLength, '0');
    for (let i = 0; i < finding.byteLength; i++) {
      out[i] = hexTarget.charCodeAt(i) & 0xff;
    }
    return out;
  }

  const bytesPerChar = finding.encoding === 'UTF-16LE' ? 2 : 1;
  const charCapacity = Math.floor(finding.byteLength / bytesPerChar);
  const writeLen = Math.min(plainTarget.length, charCapacity);

  for (let i = 0; i < writeLen; i++) {
    const code = plainTarget.charCodeAt(i);
    out[i * bytesPerChar] = code & 0xff;
    if (bytesPerChar === 2) {
      out[i * bytesPerChar + 1] = 0x00;
    }
  }

  return out;
}

/**
 * Applies selected patches to a ScannedBinaryFile AND automatically repacks the binary container:
 * - For Android APKs: Recomputes DEX SHA-1 & Adler-32 headers, generates fresh `META-INF/MANIFEST.MF`
 *   and `META-INF/NULLROUTE.SF` SHA-256 digests, and repacks with 4-byte `zipalign` + updated CRC-32s.
 * - For Standalone DEX: Recomputes DEX SHA-1 & Adler-32 headers.
 * - For Windows PE (.exe / .dll): Recomputes OptionalHeader.CheckSum.
 */
export async function applyHexPatchesToFile(
  file: ScannedBinaryFile,
  strategy: PatchStrategy
): Promise<ScannedBinaryFile> {
  const newWorking = new Uint8Array(file.originalBuffer.byteLength);
  newWorking.set(file.originalBuffer);

  let anyPatched = false;
  const updatedFindings = file.findings.map((f) => {
    if (f.selected) {
      const rep = buildReplacementBytes(f, strategy);
      newWorking.set(rep, f.offset);
      anyPatched = true;
      return { ...f, patched: true };
    }
    return { ...f, patched: false };
  });

  let repackedBuffer: Uint8Array | undefined;
  let repackInfo: RepackReportInfo | undefined;

  if (anyPatched) {
    const timestamp = new Date().toISOString();

    if (file.isDEX) {
      const dexOk = await updateDexHeaderChecksumsInPlace(newWorking);
      repackedBuffer = newWorking;
      repackInfo = {
        repackedAt: timestamp,
        format: 'DEX-Repaired',
        zipAligned4Byte: false,
        dexChecksumsUpdated: dexOk,
        peChecksumUpdated: false,
        manifestDigestsUpdated: false,
        repackedSize: newWorking.byteLength,
        summary: 'DEX SHA-1 & Adler-32 headers recalculated',
      };
    } else if (file.isAPK) {
      // Update in-place workingBuffer CRC-32s and DEX checksums so Hex Inspector matches offsets
      const view = new DataView(newWorking.buffer, newWorking.byteOffset, newWorking.byteLength);
      for (const sec of file.sections) {
        const entrySlice = newWorking.subarray(
          sec.rawAddress,
          Math.min(sec.rawAddress + sec.rawSize, newWorking.length)
        );
        if (sec.isDexEntry) {
          await updateDexHeaderChecksumsInPlace(entrySlice);
        }
        const updatedCrc = computeCrc32(entrySlice);
        if (
          sec.zipLocalHeaderOffset !== undefined &&
          sec.zipLocalHeaderOffset + 18 <= newWorking.length
        ) {
          view.setUint32(sec.zipLocalHeaderOffset + 14, updatedCrc, true);
        }
        if (
          sec.zipCentralHeaderOffset !== undefined &&
          sec.zipCentralHeaderOffset + 20 <= newWorking.length
        ) {
          view.setUint32(sec.zipCentralHeaderOffset + 16, updatedCrc, true);
        }
      }

      // Build fully repacked 4-byte zipaligned APK with META-INF/MANIFEST.MF SHA-256 digests
      const { repackedBuffer: alignedApk, manifestEntriesUpdated } =
        await repackApkWithManifestAndZipalign(newWorking, file.sections);
      repackedBuffer = alignedApk;
      repackInfo = {
        repackedAt: timestamp,
        format: 'APK-ZipAligned',
        zipAligned4Byte: true,
        dexChecksumsUpdated: true,
        peChecksumUpdated: false,
        manifestDigestsUpdated: true,
        repackedSize: alignedApk.byteLength,
        summary: `4-Byte ZipAligned · DEX SHA-1/Adler-32 · META-INF (${manifestEntriesUpdated} SHA-256 digests)`,
      };
    } else if (file.isPE) {
      const peOk = updatePEHeaderChecksumInPlace(newWorking);
      repackedBuffer = newWorking;
      repackInfo = {
        repackedAt: timestamp,
        format: 'PE-Checksum-Updated',
        zipAligned4Byte: false,
        dexChecksumsUpdated: false,
        peChecksumUpdated: peOk,
        manifestDigestsUpdated: false,
        repackedSize: newWorking.byteLength,
        summary: 'PE OptionalHeader CheckSum recalculated (0B delta)',
      };
    } else {
      repackedBuffer = newWorking;
      repackInfo = {
        repackedAt: timestamp,
        format: 'Raw-Patched',
        zipAligned4Byte: false,
        dexChecksumsUpdated: false,
        peChecksumUpdated: false,
        manifestDigestsUpdated: false,
        repackedSize: newWorking.byteLength,
        summary: 'In-place binary buffer repacked (0B delta)',
      };
    }
  }

  const newSha = await computeSha256(repackedBuffer || newWorking);

  return {
    ...file,
    workingBuffer: newWorking,
    repackedBuffer,
    repackInfo,
    workingSha256: newSha,
    findings: updatedFindings,
    isModified: anyPatched,
  };
}

/**
 * Restores a ScannedBinaryFile to its untouched original binary buffer.
 */
export function restoreOriginalFile(file: ScannedBinaryFile): ScannedBinaryFile {
  const restored = new Uint8Array(file.originalBuffer.byteLength);
  restored.set(file.originalBuffer);

  return {
    ...file,
    workingBuffer: restored,
    repackedBuffer: undefined,
    repackInfo: undefined,
    workingSha256: file.originalSha256,
    isModified: false,
    findings: file.findings.map((f) => ({ ...f, patched: false })),
  };
}

/**
 * Builds a complete repacked `.zip` bundle containing all patched & repacked binaries
 * in their relative folder paths plus the generated `hosts`, firewall scripts, and audit report.
 */
export function buildCompleteRepackedBundleZip(
  files: ScannedBinaryFile[],
  extraTextFiles: { name: string; content: string }[]
): Uint8Array {
  const entries: ZipEntryRecord[] = [];

  for (const f of files) {
    const payload = f.repackedBuffer || f.workingBuffer;
    entries.push({
      name: f.relativePath || f.name,
      data: payload,
    });
  }

  for (const extra of extraTextFiles) {
    entries.push({
      name: extra.name,
      data: new TextEncoder().encode(extra.content),
    });
  }

  return buildStoreZipArchive(entries, true);
}

/**
 * Builds a realistic Android APK (valid ZIP container with AndroidManifest.xml, classes.dex
 * with valid DEX 039 header/SHA-1/Adler-32, and lib/arm64-v8a/libnative-telemetry.so ELF64).
 */
async function createSampleAndroidApkBuffer(): Promise<Uint8Array> {
  const manifestBuf = new Uint8Array(512);
  const mView = new DataView(manifestBuf.buffer);
  mView.setUint32(0, 0x00080003, true); // AXML magic
  mView.setUint32(4, 512, true);
  const manifestWideStrings = [
    { offset: 0x40, text: 'https://firebaselogging-pa.googleapis.com/v1/firelog/legacy/batchlog' },
    { offset: 0xe0, text: 'https://csi.gstatic.com/csi' },
  ];
  for (const w of manifestWideStrings) {
    for (let i = 0; i < w.text.length; i++) {
      manifestBuf[w.offset + i * 2] = w.text.charCodeAt(i);
      manifestBuf[w.offset + i * 2 + 1] = 0x00;
    }
  }

  const dexBuf = new Uint8Array(1536);
  const dView = new DataView(dexBuf.buffer);
  const dexMagic = [0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x39, 0x00];
  dexBuf.set(dexMagic, 0);
  dView.setUint32(0x20, dexBuf.byteLength, true);
  dView.setUint32(0x24, 0x70, true);
  dView.setUint32(0x28, 0x12345678, true);
  dView.setUint32(0x38, 7, true);
  dView.setUint32(0x3c, 0x70, true);
  dView.setUint32(0x68, dexBuf.byteLength - 0x100, true);
  dView.setUint32(0x6c, 0x100, true);

  const dexTelemetryStrings = [
    { offset: 0x120, text: 'https://app-measurement.com/a' },
    { offset: 0x160, text: 'https://launches.appsflyer.com/api/v6.12/androidevent' },
    { offset: 0x1c0, text: 'https://app.adjust.com/session' },
    { offset: 0x200, text: 'https://graph.facebook.com/v18.0/activities' },
    { offset: 0x250, text: 'https://sdk.iad-01.braze.com/api/v3/data' },
    { offset: 0x2a0, text: 'https://auction.unityads.unity3d.com/v4/test' },
    { offset: 0x300, text: 'ONESIGNAL_CFG=aHR0cHM6Ly9vbmVzaWduYWwuY29tL2FwaS92MS9wbGF5ZXJz' },
  ];

  for (const s of dexTelemetryStrings) {
    dexBuf[s.offset - 1] = s.text.length & 0x7f;
    for (let i = 0; i < s.text.length; i++) {
      dexBuf[s.offset + i] = s.text.charCodeAt(i);
    }
    dexBuf[s.offset + s.text.length] = 0x00;
  }
  await updateDexHeaderChecksumsInPlace(dexBuf);

  const soBuf = new Uint8Array(768);
  const soView = new DataView(soBuf.buffer);
  soBuf.set([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00], 0);
  soView.setUint16(0x10, 3, true);
  soView.setUint16(0x12, 0xb7, true);

  const nativeAscii = 'https://crashlyticsreports-pa.googleapis.com/v1/firelog/legacy/batchlog';
  for (let i = 0; i < nativeAscii.length; i++) {
    soBuf[0x100 + i] = nativeAscii.charCodeAt(i);
  }
  const nativeXor = 'https://o450999.ingest.sentry.io/api/99/envelope/';
  for (let i = 0; i < nativeXor.length; i++) {
    soBuf[0x180 + i] = (nativeXor.charCodeAt(i) & 0xff) ^ 0x4a;
  }

  return buildStoreZipArchive(
    [
      { name: 'AndroidManifest.xml', data: manifestBuf },
      { name: 'classes.dex', data: dexBuf },
      { name: 'lib/arm64-v8a/libnative-telemetry.so', data: soBuf },
    ],
    true
  );
}

/**
 * Creates a realistic suite of sample binaries in memory.
 */
export async function createSampleBinarySuite(): Promise<ScannedBinaryFile[]> {
  const scannedFiles: ScannedBinaryFile[] = [];

  const apkBuffer = await createSampleAndroidApkBuffer();
  const scannedApk = await scanBinaryBuffer(
    'sample-apk-1',
    'DroidPulseMobile-release.apk',
    'apk/DroidPulseMobile-release.apk',
    apkBuffer
  );
  scannedFiles.push(scannedApk);

  const peSamples = [
    {
      name: 'StudioDesktopClient.exe',
      relativePath: 'bin/StudioDesktopClient.exe',
      size: 4096,
      sec1Name: '.text',
      sec2Name: '.rdata',
      asciiStrings: [
        { offset: 0x0420, text: 'https://o450123.ingest.sentry.io/api/54321/envelope/' },
        { offset: 0x0480, text: 'https://api.mixpanel.com/track/?ip=1' },
        { offset: 0x04d0, text: 'https://api2.amplitude.com/2/httpapi' },
        { offset: 0x0520, text: 'https://api.segment.io/v1/batch' },
        { offset: 0x0560, text: 'https://www.google-analytics.com/mp/collect' },
        { offset: 0x05c0, text: 'https://telemetry.studiocloud-app.io/v2/beacon' },
      ],
      wideStrings: [
        { offset: 0x0640, text: 'https://dc.services.visualstudio.com/v2/track' },
        { offset: 0x06c0, text: 'https://vortex.data.microsoft.com/collect/v1' },
        { offset: 0x0740, text: 'https://rs.fullstory.com/rec/bundle' },
      ],
      xorStrings: [
        { offset: 0x07d0, key: 0x5a, text: 'https://r.lr-ingest.io/i/v2/events' },
      ],
    },
    {
      name: 'ObfuscatedStealthAgent.dll',
      relativePath: 'bin/plugins/ObfuscatedStealthAgent.dll',
      size: 3584,
      sec1Name: '.vmp0',
      sec2Name: '.rdata',
      asciiStrings: [
        { offset: 0x0420, text: 'CFG_ENDPOINT=aHR0cHM6Ly9hcGkubWl4cGFuZWwuY29tL2VuZ2FnZQ==' },
        {
          offset: 0x0480,
          text: 'TELEM_B64=aHR0cHM6Ly92b3J0ZXguZGF0YS5taWNyb3NvZnQuY29tL2NvbGxlY3QvdjE=',
        },
        { offset: 0x0510, text: '/meti/1/ipa/moc.rabllor.ipa//:sptth' },
        { offset: 0x0570, text: 'uggcf://ncc.cbfgubt.pbz/ongpu/' },
        {
          offset: 0x05c0,
          text: '68747470733a2f2f617069322e6272616e63682e696f2f76312f6f70656e',
        },
      ],
      wideStrings: [],
      xorStrings: [
        { offset: 0x0650, key: 0x33, text: 'https://o998811.ingest.sentry.io/api/1/store/' },
        { offset: 0x06b0, key: 0x7f, text: 'https://cc-api-data.adobe.io/ingest/v2' },
        { offset: 0x0710, key: 0x42, text: 'https://crashlyticsreports-pa.googleapis.com/v1' },
      ],
    },
  ];

  for (let idx = 0; idx < peSamples.length; idx++) {
    const spec = peSamples[idx];
    const buf = new Uint8Array(spec.size);
    const view = new DataView(buf.buffer);

    buf[0] = 0x4d;
    buf[1] = 0x5a;
    buf[2] = 0x90;
    view.setUint32(0x3c, 0x80, true);

    const dosMsg = 'This program cannot be run in DOS mode.\r\r\n$';
    for (let i = 0; i < dosMsg.length; i++) {
      buf[0x40 + i] = dosMsg.charCodeAt(i);
    }

    buf[0x80] = 0x50;
    buf[0x81] = 0x45;
    buf[0x82] = 0x00;
    buf[0x83] = 0x00;
    view.setUint16(0x84, 0x8664, true);
    view.setUint16(0x86, 2, true);
    view.setUint32(0x88, 0x67229400, true);
    view.setUint16(0x94, 0xf0, true);
    view.setUint16(0x96, spec.name.endsWith('.dll') ? 0x2022 : 0x0022, true);
    view.setUint16(0x98, 0x020b, true);

    const secTable = 0x188;

    for (let i = 0; i < spec.sec1Name.length; i++) {
      buf[secTable + i] = spec.sec1Name.charCodeAt(i);
    }
    view.setUint32(secTable + 8, 0x200, true);
    view.setUint32(secTable + 12, 0x1000, true);
    view.setUint32(secTable + 16, 0x200, true);
    view.setUint32(secTable + 20, 0x200, true);

    const sec2Offset = secTable + 40;
    for (let i = 0; i < spec.sec2Name.length; i++) {
      buf[sec2Offset + i] = spec.sec2Name.charCodeAt(i);
    }
    view.setUint32(sec2Offset + 8, spec.size - 0x400, true);
    view.setUint32(sec2Offset + 12, 0x2000, true);
    view.setUint32(sec2Offset + 16, spec.size - 0x400, true);
    view.setUint32(sec2Offset + 20, 0x400, true);

    const opcodes = [
      0x48, 0x89, 0x5c, 0x24, 0x08, 0x57, 0x48, 0x83, 0xec, 0x20, 0x48, 0x8b,
      0xd9, 0xe8, 0x10, 0x01, 0x00, 0x00, 0x48, 0x83, 0xc4, 0x20, 0x5f, 0xc3,
      0x90, 0xcc,
    ];
    for (let i = 0x200; i < 0x400; i++) {
      buf[i] = opcodes[(i - 0x200) % opcodes.length];
    }

    for (const s of spec.asciiStrings) {
      for (let i = 0; i < s.text.length; i++) {
        if (s.offset + i < buf.length) {
          buf[s.offset + i] = s.text.charCodeAt(i);
        }
      }
    }

    for (const w of spec.wideStrings) {
      for (let i = 0; i < w.text.length; i++) {
        const pos = w.offset + i * 2;
        if (pos + 1 < buf.length) {
          buf[pos] = w.text.charCodeAt(i);
          buf[pos + 1] = 0x00;
        }
      }
    }

    for (const x of spec.xorStrings) {
      for (let i = 0; i < x.text.length; i++) {
        if (x.offset + i < buf.length) {
          buf[x.offset + i] = (x.text.charCodeAt(i) & 0xff) ^ x.key;
        }
      }
    }

    updatePEHeaderChecksumInPlace(buf);

    const scanned = await scanBinaryBuffer(
      `sample-pe-${idx + 1}`,
      spec.name,
      spec.relativePath,
      buf
    );
    scannedFiles.push(scanned);
  }

  return scannedFiles;
}
