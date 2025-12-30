import React, { useRef } from 'react';
import type { ExifMetadataViewerData, ExifMetadata } from './tool-types';

// EXIF tag IDs
const EXIF_TAGS: Record<number, keyof ExifMetadata> = {
  0x010f: 'make',
  0x0110: 'model',
  0x0132: 'dateTime',
  0x9003: 'dateTimeOriginal',
  0x829a: 'exposureTime',
  0x829d: 'fNumber',
  0x8827: 'iso',
  0x920a: 'focalLength',
  0x0131: 'software',
  0x0112: 'orientation',
  0xa002: 'imageWidth',
  0xa003: 'imageHeight',
  0x013b: 'artist',
  0x8298: 'copyright'
};

// Parse EXIF data from ArrayBuffer
const parseExif = (buffer: ArrayBuffer): ExifMetadata | null => {
  const view = new DataView(buffer);

  // Check for JPEG magic number
  if (view.getUint16(0) !== 0xFFD8) {
    return null;
  }

  let offset = 2;
  const length = view.byteLength;

  while (offset < length) {
    if (view.getUint8(offset) !== 0xFF) {
      offset++;
      continue;
    }

    const marker = view.getUint8(offset + 1);

    // APP1 marker (EXIF)
    if (marker === 0xE1) {
      const exifLength = view.getUint16(offset + 2);
      const exifData = buffer.slice(offset + 4, offset + 2 + exifLength);
      return parseExifData(exifData);
    }

    // Skip other markers
    if (marker >= 0xE0 && marker <= 0xEF) {
      offset += 2 + view.getUint16(offset + 2);
    } else if (marker === 0xD9) {
      // End of image
      break;
    } else {
      offset += 2;
    }
  }

  return null;
};

const parseExifData = (buffer: ArrayBuffer): ExifMetadata | null => {
  const view = new DataView(buffer);

  // Check for "Exif" header
  const exifHeader = String.fromCharCode(
    view.getUint8(0),
    view.getUint8(1),
    view.getUint8(2),
    view.getUint8(3)
  );

  if (exifHeader !== 'Exif') {
    return null;
  }

  // TIFF header starts at offset 6
  const tiffOffset = 6;
  const littleEndian = view.getUint16(tiffOffset) === 0x4949;

  const getUint16 = (o: number) => view.getUint16(o, littleEndian);
  const getUint32 = (o: number) => view.getUint32(o, littleEndian);

  // Get IFD0 offset
  const ifd0Offset = tiffOffset + getUint32(tiffOffset + 4);

  const metadata: ExifMetadata = {};

  // Parse IFD0
  const parseIFD = (ifdOffset: number) => {
    const entryCount = getUint16(ifdOffset);

    for (let i = 0; i < entryCount; i++) {
      const entryOffset = ifdOffset + 2 + i * 12;
      const tag = getUint16(entryOffset);
      const type = getUint16(entryOffset + 2);
      const count = getUint32(entryOffset + 4);

      const tagName = EXIF_TAGS[tag];
      if (!tagName) continue;

      let value: string | number | undefined;

      // Type 2 = ASCII
      if (type === 2) {
        let strOffset = entryOffset + 8;
        if (count > 4) {
          strOffset = tiffOffset + getUint32(entryOffset + 8);
        }
        let str = '';
        for (let j = 0; j < count - 1; j++) {
          str += String.fromCharCode(view.getUint8(strOffset + j));
        }
        value = str;
      }
      // Type 3 = SHORT (uint16)
      else if (type === 3) {
        value = getUint16(entryOffset + 8);
      }
      // Type 4 = LONG (uint32)
      else if (type === 4) {
        value = getUint32(entryOffset + 8);
      }
      // Type 5 = RATIONAL
      else if (type === 5) {
        const ratOffset = tiffOffset + getUint32(entryOffset + 8);
        const numerator = getUint32(ratOffset);
        const denominator = getUint32(ratOffset + 4);
        if (tagName === 'exposureTime') {
          value = denominator > 1 ? `1/${Math.round(denominator / numerator)}` : `${numerator}`;
        } else if (tagName === 'fNumber') {
          value = `f/${(numerator / denominator).toFixed(1)}`;
        } else if (tagName === 'focalLength') {
          value = `${Math.round(numerator / denominator)}mm`;
        } else {
          value = numerator / denominator;
        }
      }

      if (value !== undefined) {
        (metadata as Record<string, unknown>)[tagName] = value;
      }
    }
  };

  parseIFD(ifd0Offset);

  return Object.keys(metadata).length > 0 ? metadata : null;
};

// Format GPS coordinate
const formatGpsCoordinate = (coord: number, isLat: boolean): string => {
  const direction = isLat ? (coord >= 0 ? 'N' : 'S') : (coord >= 0 ? 'E' : 'W');
  const absCoord = Math.abs(coord);
  const degrees = Math.floor(absCoord);
  const minutes = Math.floor((absCoord - degrees) * 60);
  const seconds = ((absCoord - degrees) * 60 - minutes) * 60;
  return `${degrees}° ${minutes}' ${seconds.toFixed(2)}" ${direction}`;
};

const ExifMetadataViewerToolComponent = ({
  data,
  onChange,
  onLoadFile
}: {
  data: ExifMetadataViewerData | undefined;
  onChange: (next: ExifMetadataViewerData) => void;
  onLoadFile: (file: File) => Promise<void>;
}) => {
  const fileInputRef = useRef<HTMLInputElement>(null);
  const fileName = data?.fileName;
  const metadata = data?.metadata;
  const loading = data?.loading ?? false;
  const error = data?.error;

  const handleFileSelect = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    if (!file.type.startsWith('image/')) {
      onChange({ error: 'Please select an image file' });
      return;
    }

    await onLoadFile(file);
  };

  const handleClear = () => {
    onChange({});
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const renderMetadataRow = (label: string, value: string | number | undefined) => {
    if (value === undefined) return null;
    return (
      <div className="xcalibr-flex xcalibr-justify-between xcalibr-py-1 xcalibr-border-b xcalibr-border-[#333]">
        <span className="xcalibr-text-gray-400">{label}</span>
        <span className="xcalibr-text-white">{value}</span>
      </div>
    );
  };

  return (
    <div className="xcalibr-flex xcalibr-flex-col xcalibr-gap-3">
      <div className="xcalibr-flex xcalibr-gap-2">
        <input
          ref={fileInputRef}
          type="file"
          accept="image/*"
          onChange={handleFileSelect}
          className="xcalibr-flex-1 xcalibr-bg-[#1e1e1e] xcalibr-border xcalibr-border-[#333] xcalibr-rounded xcalibr-px-2 xcalibr-py-1 xcalibr-text-sm xcalibr-text-white file:xcalibr-bg-[#333] file:xcalibr-text-white file:xcalibr-border-0 file:xcalibr-px-2 file:xcalibr-py-1 file:xcalibr-rounded file:xcalibr-mr-2 file:xcalibr-cursor-pointer"
          disabled={loading}
        />
        {(metadata || error) && (
          <button
            onClick={handleClear}
            className="xcalibr-bg-[#333] xcalibr-text-gray-300 xcalibr-px-3 xcalibr-py-1 xcalibr-rounded xcalibr-text-sm hover:xcalibr-bg-[#444]"
          >
            Clear
          </button>
        )}
      </div>

      {loading && (
        <div className="xcalibr-text-sm xcalibr-text-gray-400 xcalibr-text-center xcalibr-py-2">
          Reading metadata...
        </div>
      )}

      {error && (
        <div className="xcalibr-bg-red-500/20 xcalibr-border xcalibr-border-red-500/50 xcalibr-rounded xcalibr-p-2 xcalibr-text-sm xcalibr-text-red-400">
          {error}
        </div>
      )}

      {metadata && (
        <div className="xcalibr-bg-[#1e1e1e] xcalibr-border xcalibr-border-[#333] xcalibr-rounded xcalibr-p-3 xcalibr-text-sm">
          {fileName && (
            <div className="xcalibr-text-xs xcalibr-text-gray-500 xcalibr-mb-2 xcalibr-truncate">
              {fileName}
            </div>
          )}

          {(metadata.make || metadata.model) && (
            <div className="xcalibr-mb-3">
              <div className="xcalibr-text-xs xcalibr-text-blue-400 xcalibr-uppercase xcalibr-mb-1">Camera</div>
              {renderMetadataRow('Make', metadata.make)}
              {renderMetadataRow('Model', metadata.model)}
            </div>
          )}

          {(metadata.exposureTime || metadata.fNumber || metadata.iso || metadata.focalLength) && (
            <div className="xcalibr-mb-3">
              <div className="xcalibr-text-xs xcalibr-text-blue-400 xcalibr-uppercase xcalibr-mb-1">Exposure</div>
              {renderMetadataRow('Shutter Speed', metadata.exposureTime)}
              {renderMetadataRow('Aperture', metadata.fNumber)}
              {renderMetadataRow('ISO', metadata.iso)}
              {renderMetadataRow('Focal Length', metadata.focalLength)}
            </div>
          )}

          {(metadata.dateTime || metadata.dateTimeOriginal) && (
            <div className="xcalibr-mb-3">
              <div className="xcalibr-text-xs xcalibr-text-blue-400 xcalibr-uppercase xcalibr-mb-1">Date/Time</div>
              {renderMetadataRow('Date Taken', metadata.dateTimeOriginal || metadata.dateTime)}
            </div>
          )}

          {(metadata.imageWidth || metadata.imageHeight) && (
            <div className="xcalibr-mb-3">
              <div className="xcalibr-text-xs xcalibr-text-blue-400 xcalibr-uppercase xcalibr-mb-1">Dimensions</div>
              {renderMetadataRow('Size', `${metadata.imageWidth} x ${metadata.imageHeight}`)}
              {metadata.orientation !== undefined && metadata.orientation !== 1 && (
                renderMetadataRow('Orientation', `Rotated (${metadata.orientation})`)
              )}
            </div>
          )}

          {(metadata.gpsLatitude !== undefined && metadata.gpsLongitude !== undefined) && (
            <div className="xcalibr-mb-3">
              <div className="xcalibr-text-xs xcalibr-text-blue-400 xcalibr-uppercase xcalibr-mb-1">GPS Location</div>
              <div className="xcalibr-text-xs xcalibr-text-white xcalibr-mb-1">
                {formatGpsCoordinate(metadata.gpsLatitude, true)}
                <br />
                {formatGpsCoordinate(metadata.gpsLongitude, false)}
              </div>
              {metadata.gpsAltitude !== undefined && (
                <div className="xcalibr-text-xs xcalibr-text-gray-400 xcalibr-mb-1">
                  Altitude: {metadata.gpsAltitude}m
                </div>
              )}
              <a
                href={`https://www.google.com/maps?q=${metadata.gpsLatitude},${metadata.gpsLongitude}`}
                target="_blank"
                rel="noopener noreferrer"
                className="xcalibr-text-xs xcalibr-text-blue-400 hover:xcalibr-underline"
              >
                View on Google Maps →
              </a>
            </div>
          )}

          {(metadata.artist || metadata.copyright || metadata.software) && (
            <div>
              <div className="xcalibr-text-xs xcalibr-text-blue-400 xcalibr-uppercase xcalibr-mb-1">Other</div>
              {renderMetadataRow('Artist', metadata.artist)}
              {renderMetadataRow('Copyright', metadata.copyright)}
              {renderMetadataRow('Software', metadata.software)}
            </div>
          )}
        </div>
      )}

      {!metadata && !loading && !error && (
        <div className="xcalibr-text-sm xcalibr-text-gray-400 xcalibr-text-center xcalibr-py-4">
          Select an image to view EXIF metadata
        </div>
      )}
    </div>
  );
};

export { parseExif };

export class ExifMetadataViewerTool {
  static Component = ExifMetadataViewerToolComponent;
}
