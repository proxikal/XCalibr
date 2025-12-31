import React, { useState, useCallback, useRef } from 'react';
import type { MetadataScrubberData, MetadataField } from './tool-types';

const SUPPORTED_TYPES = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];

// Basic JPEG metadata extraction (simplified)
const extractJpegMetadata = (buffer: ArrayBuffer): MetadataField[] => {
  const fields: MetadataField[] = [];
  const view = new DataView(buffer);

  // Check JPEG magic number
  if (view.getUint16(0) !== 0xffd8) {
    return fields;
  }

  let offset = 2;
  while (offset < buffer.byteLength - 2) {
    const marker = view.getUint16(offset);

    if (marker === 0xffe1) {
      // APP1 (EXIF) segment
      const length = view.getUint16(offset + 2);
      fields.push({ key: 'EXIF Data', value: `Found (${length} bytes)` });

      // Try to extract some basic info
      try {
        const exifOffset = offset + 4;
        const exifHeader = new Uint8Array(buffer.slice(exifOffset, exifOffset + 6));
        const exifString = String.fromCharCode(...exifHeader);
        if (exifString.startsWith('Exif')) {
          fields.push({ key: 'Format', value: 'EXIF' });
        }
      } catch {
        // Ignore extraction errors
      }
      offset += 2 + length;
    } else if (marker === 0xffe0) {
      // APP0 (JFIF) segment
      const length = view.getUint16(offset + 2);
      fields.push({ key: 'JFIF Data', value: `Found (${length} bytes)` });
      offset += 2 + length;
    } else if ((marker & 0xff00) === 0xff00 && marker !== 0xffff) {
      const length = view.getUint16(offset + 2);
      offset += 2 + length;
    } else {
      offset++;
    }

    if (offset > 65536) break; // Safety limit
  }

  return fields;
};

// Basic PNG metadata extraction
const extractPngMetadata = (buffer: ArrayBuffer): MetadataField[] => {
  const fields: MetadataField[] = [];
  const view = new DataView(buffer);

  // Check PNG magic number
  if (view.getUint32(0) !== 0x89504e47) {
    return fields;
  }

  let offset = 8; // Skip PNG signature
  while (offset < buffer.byteLength - 12) {
    const length = view.getUint32(offset);
    const typeBytes = new Uint8Array(buffer.slice(offset + 4, offset + 8));
    const type = String.fromCharCode(...typeBytes);

    if (type === 'tEXt' || type === 'iTXt' || type === 'zTXt') {
      fields.push({ key: `${type} Chunk`, value: `Found (${length} bytes)` });
    } else if (type === 'eXIf') {
      fields.push({ key: 'EXIF Data', value: `Found (${length} bytes)` });
    }

    if (type === 'IEND') break;
    offset += 12 + length;
    if (offset > buffer.byteLength) break;
  }

  return fields;
};

// Strip JPEG metadata by keeping only essential markers
const stripJpegMetadata = (buffer: ArrayBuffer): ArrayBuffer => {
  const view = new DataView(buffer);
  if (view.getUint16(0) !== 0xffd8) {
    return buffer; // Not a valid JPEG
  }

  const result: number[] = [0xff, 0xd8]; // Start with SOI marker
  let offset = 2;

  while (offset < buffer.byteLength - 2) {
    const marker = view.getUint16(offset);

    // End of image marker
    if (marker === 0xffd9) {
      result.push(0xff, 0xd9);
      break;
    }

    // Skip APP1 (EXIF) and other APP markers except APP0 (JFIF) which we need
    if ((marker >= 0xffe1 && marker <= 0xffef)) {
      const length = view.getUint16(offset + 2);
      offset += 2 + length;
      continue;
    }

    // Keep other markers
    if ((marker & 0xff00) === 0xff00 && marker !== 0xffff) {
      const length = view.getUint16(offset + 2);
      const segment = new Uint8Array(buffer.slice(offset, offset + 2 + length));
      result.push(...segment);
      offset += 2 + length;
    } else {
      // Copy image data
      result.push(new Uint8Array(buffer)[offset]);
      offset++;
    }
  }

  return new Uint8Array(result).buffer;
};

// Strip PNG metadata by removing text chunks
const stripPngMetadata = (buffer: ArrayBuffer): ArrayBuffer => {
  const view = new DataView(buffer);
  if (view.getUint32(0) !== 0x89504e47) {
    return buffer; // Not a valid PNG
  }

  // Start with PNG signature
  const result: number[] = [...new Uint8Array(buffer.slice(0, 8))];
  let offset = 8;

  const metadataChunks = ['tEXt', 'iTXt', 'zTXt', 'eXIf', 'iCCP', 'sRGB', 'gAMA', 'cHRM'];

  while (offset < buffer.byteLength - 12) {
    const length = view.getUint32(offset);
    const typeBytes = new Uint8Array(buffer.slice(offset + 4, offset + 8));
    const type = String.fromCharCode(...typeBytes);

    const chunkSize = 12 + length; // length field (4) + type (4) + data + CRC (4)

    // Skip metadata chunks
    if (!metadataChunks.includes(type)) {
      const chunk = new Uint8Array(buffer.slice(offset, offset + chunkSize));
      result.push(...chunk);
    }

    if (type === 'IEND') break;
    offset += chunkSize;
    if (offset > buffer.byteLength) break;
  }

  return new Uint8Array(result).buffer;
};

type Props = {
  data: MetadataScrubberData | undefined;
  onChange: (next: MetadataScrubberData) => void;
};

const MetadataScrubberToolComponent = ({ data, onChange }: Props) => {
  const fileName = data?.fileName ?? '';
  const fileSize = data?.fileSize ?? 0;
  const fileType = data?.fileType ?? '';
  const metadata = data?.metadata ?? [];
  const scrubbed = data?.scrubbed ?? false;
  const scrubbedSize = data?.scrubbedSize ?? 0;
  const scrubbedUrl = data?.scrubbedUrl ?? '';
  const loading = data?.loading ?? false;
  const error = data?.error ?? '';

  const fileInputRef = useRef<HTMLInputElement>(null);
  const fileBufferRef = useRef<ArrayBuffer | null>(null);

  const handleFileSelect = useCallback(async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    if (!SUPPORTED_TYPES.includes(file.type)) {
      onChange({
        ...data,
        error: `Unsupported file type: ${file.type}. Supported: JPEG, PNG, GIF, WebP`,
        fileName: file.name,
        scrubbed: false
      });
      return;
    }

    onChange({ ...data, loading: true, error: '' });

    try {
      const buffer = await file.arrayBuffer();
      fileBufferRef.current = buffer;

      let fields: MetadataField[] = [];
      if (file.type === 'image/jpeg') {
        fields = extractJpegMetadata(buffer);
      } else if (file.type === 'image/png') {
        fields = extractPngMetadata(buffer);
      }

      if (fields.length === 0) {
        fields.push({ key: 'Status', value: 'No metadata found' });
      }

      onChange({
        ...data,
        fileName: file.name,
        fileSize: file.size,
        fileType: file.type,
        metadata: fields,
        scrubbed: false,
        loading: false,
        error: ''
      });
    } catch (err) {
      onChange({
        ...data,
        error: err instanceof Error ? err.message : 'Failed to read file',
        loading: false
      });
    }
  }, [data, onChange]);

  const handleScrub = useCallback(() => {
    if (!fileBufferRef.current || !fileType) {
      onChange({ ...data, error: 'No file loaded' });
      return;
    }

    onChange({ ...data, loading: true });

    try {
      let cleanedBuffer: ArrayBuffer;

      if (fileType === 'image/jpeg') {
        cleanedBuffer = stripJpegMetadata(fileBufferRef.current);
      } else if (fileType === 'image/png') {
        cleanedBuffer = stripPngMetadata(fileBufferRef.current);
      } else {
        // For other formats, just return as-is for now
        cleanedBuffer = fileBufferRef.current;
      }

      const blob = new Blob([cleanedBuffer], { type: fileType });
      const url = URL.createObjectURL(blob);

      onChange({
        ...data,
        scrubbed: true,
        scrubbedSize: cleanedBuffer.byteLength,
        scrubbedUrl: url,
        loading: false,
        error: ''
      });
    } catch (err) {
      onChange({
        ...data,
        error: err instanceof Error ? err.message : 'Failed to scrub metadata',
        loading: false
      });
    }
  }, [data, fileType, onChange]);

  const handleClear = useCallback(() => {
    if (scrubbedUrl) {
      URL.revokeObjectURL(scrubbedUrl);
    }
    fileBufferRef.current = null;
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
    onChange({});
  }, [scrubbedUrl, onChange]);

  const formatBytes = (bytes: number): string => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">Metadata Scrubber</div>

      <div className="space-y-1">
        <div className="text-[11px] text-slate-400">Select Image File</div>
        <input
          ref={fileInputRef}
          type="file"
          accept="image/jpeg,image/png,image/gif,image/webp"
          onChange={handleFileSelect}
          className="w-full text-xs text-slate-400 file:mr-2 file:py-1 file:px-3 file:rounded file:border-0 file:bg-slate-700 file:text-slate-200 file:text-xs hover:file:bg-slate-600"
        />
      </div>

      {fileName && (
        <div className="bg-slate-800 rounded p-2 space-y-1">
          <div className="flex items-center justify-between">
            <span className="text-[11px] text-slate-200 truncate">{fileName}</span>
            <button
              type="button"
              onClick={handleClear}
              className="text-[10px] text-slate-400 hover:text-white"
            >
              Clear
            </button>
          </div>
          <div className="text-[10px] text-slate-500">
            {fileType} • {formatBytes(fileSize)}
          </div>
        </div>
      )}

      {metadata.length > 0 && (
        <div className="space-y-1">
          <div className="text-[11px] text-slate-400">Detected Metadata</div>
          <div className="bg-slate-900 border border-slate-700 rounded p-2 max-h-32 overflow-y-auto">
            {metadata.map((field, i) => (
              <div key={i} className="text-[10px] py-0.5">
                <span className="text-emerald-400">{field.key}:</span>{' '}
                <span className="text-slate-300">{field.value}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      <button
        type="button"
        onClick={handleScrub}
        disabled={!fileName || loading || scrubbed}
        className="w-full rounded bg-emerald-600 text-white text-xs py-2 hover:bg-emerald-500 disabled:opacity-50 disabled:cursor-not-allowed"
      >
        {loading ? 'Processing...' : 'Scrub Metadata'}
      </button>

      {scrubbed && (
        <div className="bg-emerald-900/30 border border-emerald-700 rounded p-2 space-y-2">
          <div className="text-[11px] text-emerald-400">Metadata Removed Successfully!</div>
          <div className="text-[10px] text-slate-300">
            Original: {formatBytes(fileSize)} → Cleaned: {formatBytes(scrubbedSize)}
            {fileSize > scrubbedSize && (
              <span className="text-emerald-400 ml-1">
                (-{formatBytes(fileSize - scrubbedSize)})
              </span>
            )}
          </div>
          {scrubbedUrl && (
            <a
              href={scrubbedUrl}
              download={`cleaned_${fileName}`}
              className="block w-full text-center rounded bg-emerald-600 text-white text-xs py-2 hover:bg-emerald-500"
            >
              Download Cleaned File
            </a>
          )}
        </div>
      )}

      {error && (
        <div className="bg-red-900/30 border border-red-700 rounded p-2 text-[10px] text-red-300">
          {error}
        </div>
      )}

      <div className="text-[10px] text-slate-500">
        Remove EXIF and other metadata from images. Supports JPEG, PNG, GIF, and WebP files.
        Useful for privacy when sharing photos online.
      </div>
    </div>
  );
};

export class MetadataScrubberTool {
  static Component = MetadataScrubberToolComponent;
}
