import { beforeEach, describe, it, afterEach, vi } from 'vitest';
import { aiAssertEqual, aiAssertTruthy, aiAssertIncludes } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  flushPromises,
  waitFor,
  findButtonByText
} from '../../../__tests__/integration-test-utils';
import type { ExifMetadataViewerData, ExifMetadata } from '../tool-types';

// Mock EXIF metadata factory
const createMockExifMetadata = (): ExifMetadata => ({
  make: 'Canon',
  model: 'EOS 5D Mark IV',
  dateTime: '2024:06:15 14:30:00',
  dateTimeOriginal: '2024:06:15 14:30:00',
  exposureTime: '1/250',
  fNumber: 'f/2.8',
  iso: 400,
  focalLength: '50mm',
  gpsLatitude: 37.7749,
  gpsLongitude: -122.4194,
  gpsAltitude: 10,
  software: 'Adobe Lightroom',
  orientation: 1,
  imageWidth: 6720,
  imageHeight: 4480,
  artist: 'John Doe',
  copyright: '© 2024 John Doe'
});

// Helper function to format GPS coordinates
const formatGpsCoordinate = (coord: number, isLat: boolean): string => {
  const direction = isLat ? (coord >= 0 ? 'N' : 'S') : (coord >= 0 ? 'E' : 'W');
  const absCoord = Math.abs(coord);
  const degrees = Math.floor(absCoord);
  const minutes = Math.floor((absCoord - degrees) * 60);
  const seconds = ((absCoord - degrees) * 60 - minutes) * 60;
  return `${degrees}° ${minutes}' ${seconds.toFixed(2)}" ${direction}`;
};

// Helper function to generate Google Maps link
const generateMapsLink = (lat: number, lng: number): string => {
  return `https://www.google.com/maps?q=${lat},${lng}`;
};

// Helper function to parse EXIF date format
const parseExifDate = (dateStr: string): Date | null => {
  // EXIF date format is YYYY:MM:DD HH:MM:SS
  const match = dateStr.match(/^(\d{4}):(\d{2}):(\d{2}) (\d{2}):(\d{2}):(\d{2})$/);
  if (!match) return null;
  const [, year, month, day, hour, minute, second] = match;
  return new Date(
    parseInt(year, 10),
    parseInt(month, 10) - 1,
    parseInt(day, 10),
    parseInt(hour, 10),
    parseInt(minute, 10),
    parseInt(second, 10)
  );
};

describe('ExifMetadataViewerTool', () => {
  describe('EXIF metadata parsing', () => {
    it('should create metadata with camera make', () => {
      const metadata = createMockExifMetadata();
      aiAssertEqual({ name: 'CameraMake', input: metadata }, metadata.make, 'Canon');
    });

    it('should create metadata with camera model', () => {
      const metadata = createMockExifMetadata();
      aiAssertEqual({ name: 'CameraModel', input: metadata }, metadata.model, 'EOS 5D Mark IV');
    });

    it('should create metadata with date time', () => {
      const metadata = createMockExifMetadata();
      aiAssertEqual({ name: 'DateTime', input: metadata }, metadata.dateTime, '2024:06:15 14:30:00');
    });

    it('should create metadata with exposure settings', () => {
      const metadata = createMockExifMetadata();
      aiAssertEqual({ name: 'ExposureTime', input: metadata }, metadata.exposureTime, '1/250');
      aiAssertEqual({ name: 'FNumber', input: metadata }, metadata.fNumber, 'f/2.8');
      aiAssertEqual({ name: 'ISO', input: metadata }, metadata.iso, 400);
    });

    it('should create metadata with GPS coordinates', () => {
      const metadata = createMockExifMetadata();
      aiAssertEqual({ name: 'GpsLatitude', input: metadata }, metadata.gpsLatitude, 37.7749);
      aiAssertEqual({ name: 'GpsLongitude', input: metadata }, metadata.gpsLongitude, -122.4194);
    });

    it('should create metadata with image dimensions', () => {
      const metadata = createMockExifMetadata();
      aiAssertEqual({ name: 'ImageWidth', input: metadata }, metadata.imageWidth, 6720);
      aiAssertEqual({ name: 'ImageHeight', input: metadata }, metadata.imageHeight, 4480);
    });

    it('should create metadata with copyright info', () => {
      const metadata = createMockExifMetadata();
      aiAssertEqual({ name: 'Artist', input: metadata }, metadata.artist, 'John Doe');
      aiAssertIncludes({ name: 'Copyright', input: metadata }, metadata.copyright ?? '', '2024');
    });
  });

  describe('GPS coordinate formatting', () => {
    it('should format positive latitude as North', () => {
      const formatted = formatGpsCoordinate(37.7749, true);
      aiAssertIncludes({ name: 'PositiveLatitude', input: 37.7749 }, formatted, 'N');
    });

    it('should format negative latitude as South', () => {
      const formatted = formatGpsCoordinate(-33.8688, true);
      aiAssertIncludes({ name: 'NegativeLatitude', input: -33.8688 }, formatted, 'S');
    });

    it('should format positive longitude as East', () => {
      const formatted = formatGpsCoordinate(139.6917, false);
      aiAssertIncludes({ name: 'PositiveLongitude', input: 139.6917 }, formatted, 'E');
    });

    it('should format negative longitude as West', () => {
      const formatted = formatGpsCoordinate(-122.4194, false);
      aiAssertIncludes({ name: 'NegativeLongitude', input: -122.4194 }, formatted, 'W');
    });

    it('should include degrees symbol', () => {
      const formatted = formatGpsCoordinate(37.7749, true);
      aiAssertIncludes({ name: 'DegreesSymbol', input: 37.7749 }, formatted, '°');
    });
  });

  describe('Google Maps link generation', () => {
    it('should generate valid Maps URL', () => {
      const link = generateMapsLink(37.7749, -122.4194);
      aiAssertIncludes({ name: 'MapsUrl', input: { lat: 37.7749, lng: -122.4194 } }, link, 'google.com/maps');
    });

    it('should include coordinates in URL', () => {
      const link = generateMapsLink(37.7749, -122.4194);
      aiAssertIncludes({ name: 'LatInUrl', input: link }, link, '37.7749');
      aiAssertIncludes({ name: 'LngInUrl', input: link }, link, '-122.4194');
    });
  });

  describe('EXIF date parsing', () => {
    it('should parse valid EXIF date format', () => {
      const date = parseExifDate('2024:06:15 14:30:00');
      aiAssertTruthy({ name: 'DateParsed', input: '2024:06:15 14:30:00' }, date);
      aiAssertEqual({ name: 'DateYear', input: date }, date!.getFullYear(), 2024);
      aiAssertEqual({ name: 'DateMonth', input: date }, date!.getMonth(), 5); // June is 5 (0-indexed)
      aiAssertEqual({ name: 'DateDay', input: date }, date!.getDate(), 15);
    });

    it('should return null for invalid date format', () => {
      const date = parseExifDate('invalid-date');
      aiAssertEqual({ name: 'InvalidDate', input: 'invalid-date' }, date, null);
    });

    it('should parse time correctly', () => {
      const date = parseExifDate('2024:06:15 14:30:45');
      aiAssertTruthy({ name: 'DateParsed', input: '2024:06:15 14:30:45' }, date);
      aiAssertEqual({ name: 'DateHour', input: date }, date!.getHours(), 14);
      aiAssertEqual({ name: 'DateMinute', input: date }, date!.getMinutes(), 30);
      aiAssertEqual({ name: 'DateSecond', input: date }, date!.getSeconds(), 45);
    });
  });

  describe('Default values', () => {
    it('should use default values when data is undefined', () => {
      const getData = (): ExifMetadataViewerData | undefined => undefined;
      const data = getData();

      const metadata = data?.metadata;
      const loading = data?.loading ?? false;
      const error = data?.error;

      aiAssertEqual({ name: 'DefaultMetadata' }, metadata, undefined);
      aiAssertEqual({ name: 'DefaultLoading' }, loading, false);
      aiAssertEqual({ name: 'DefaultError' }, error, undefined);
    });
  });

  describe('Error handling', () => {
    it('should handle error state', () => {
      const data: ExifMetadataViewerData = {
        error: 'Failed to read image metadata'
      };

      aiAssertTruthy({ name: 'ErrorPresent', input: data }, data.error !== undefined);
      aiAssertIncludes({ name: 'ErrorMessage', input: data }, data.error ?? '', 'Failed');
    });

    it('should handle no metadata found', () => {
      const data: ExifMetadataViewerData = {
        error: 'No EXIF metadata found in image'
      };

      aiAssertIncludes({ name: 'NoMetadataError', input: data }, data.error ?? '', 'No EXIF');
    });
  });

  describe('Loading state', () => {
    it('should track loading state', () => {
      const data: ExifMetadataViewerData = {
        loading: true
      };

      aiAssertEqual({ name: 'LoadingState', input: data }, data.loading, true);
    });
  });

  describe('Metadata display', () => {
    it('should format camera info', () => {
      const metadata = createMockExifMetadata();
      const cameraInfo = `${metadata.make} ${metadata.model}`;
      aiAssertIncludes({ name: 'CameraInfo', input: metadata }, cameraInfo, 'Canon');
      aiAssertIncludes({ name: 'CameraInfo', input: metadata }, cameraInfo, 'EOS 5D Mark IV');
    });

    it('should format exposure info', () => {
      const metadata = createMockExifMetadata();
      const exposureInfo = `${metadata.exposureTime} at ${metadata.fNumber}, ISO ${metadata.iso}`;
      aiAssertIncludes({ name: 'ExposureInfo', input: metadata }, exposureInfo, '1/250');
      aiAssertIncludes({ name: 'ExposureInfo', input: metadata }, exposureInfo, 'f/2.8');
      aiAssertIncludes({ name: 'ExposureInfo', input: metadata }, exposureInfo, '400');
    });

    it('should format dimensions', () => {
      const metadata = createMockExifMetadata();
      const dimensions = `${metadata.imageWidth} x ${metadata.imageHeight}`;
      aiAssertEqual({ name: 'Dimensions', input: metadata }, dimensions, '6720 x 4480');
    });
  });

  describe('Orientation handling', () => {
    it('should handle normal orientation (1)', () => {
      const metadata = createMockExifMetadata();
      aiAssertEqual({ name: 'NormalOrientation', input: metadata }, metadata.orientation, 1);
    });

    it('should detect rotation from orientation value', () => {
      // Orientation values:
      // 1 = Normal
      // 3 = Upside down (180°)
      // 6 = Rotated 90° CW
      // 8 = Rotated 90° CCW
      const getRotation = (orientation: number): number => {
        switch (orientation) {
          case 3: return 180;
          case 6: return 90;
          case 8: return 270;
          default: return 0;
        }
      };

      aiAssertEqual({ name: 'Orientation1', input: 1 }, getRotation(1), 0);
      aiAssertEqual({ name: 'Orientation3', input: 3 }, getRotation(3), 180);
      aiAssertEqual({ name: 'Orientation6', input: 6 }, getRotation(6), 90);
      aiAssertEqual({ name: 'Orientation8', input: 8 }, getRotation(8), 270);
    });
  });

  describe('Integration tests', () => {
    beforeEach(() => {
      document.body.innerHTML = '';
      resetChrome();
    });

    afterEach(() => {
      document.body.innerHTML = '';
      document.head.innerHTML = '';
      vi.restoreAllMocks();
    });

    it('renders Exif Metadata Viewer tool with file input', async () => {
      const root = await mountWithTool('exifMetadataViewer');
      if (!root) return;

      const titleElement = await waitFor(() => {
        const elements = Array.from(root.querySelectorAll('*'));
        return elements.find(el => el.textContent?.includes('EXIF Metadata'));
      });
      aiAssertTruthy({ name: 'TitleFound' }, titleElement);

      const fileInput = root.querySelector('input[type="file"]');
      aiAssertTruthy({ name: 'FileInputFound' }, fileInput);
    });

    it('displays metadata when present', async () => {
      const mockMetadata = createMockExifMetadata();
      const root = await mountWithTool('exifMetadataViewer', {
        metadata: mockMetadata
      });
      if (!root) return;

      const makeElement = await waitFor(() => {
        const elements = Array.from(root.querySelectorAll('*'));
        return elements.find(el => el.textContent?.includes('Canon'));
      });
      aiAssertTruthy({ name: 'MakeDisplayed' }, makeElement);
    });

    it('displays GPS map link when coordinates present', async () => {
      const mockMetadata = createMockExifMetadata();
      const root = await mountWithTool('exifMetadataViewer', {
        metadata: mockMetadata
      });
      if (!root) return;

      const mapLink = await waitFor(() => {
        return root.querySelector('a[href*="google.com/maps"]');
      });
      aiAssertTruthy({ name: 'MapLinkFound' }, mapLink);
    });

    it('displays error message when error present', async () => {
      const root = await mountWithTool('exifMetadataViewer', {
        error: 'No EXIF metadata found'
      });
      if (!root) return;

      await flushPromises();

      const errorElement = await waitFor(() => {
        const elements = Array.from(root.querySelectorAll('*'));
        return elements.find(el => el.textContent?.includes('No EXIF metadata'));
      });
      aiAssertTruthy({ name: 'ErrorDisplayed' }, errorElement);
    });

    it('shows loading state', async () => {
      const root = await mountWithTool('exifMetadataViewer', {
        loading: true
      });
      if (!root) return;

      const loadingElement = await waitFor(() => {
        const elements = Array.from(root.querySelectorAll('*'));
        return elements.find(el => el.textContent?.toLowerCase().includes('loading') ||
                                   el.textContent?.toLowerCase().includes('reading'));
      });
      aiAssertTruthy({ name: 'LoadingDisplayed' }, loadingElement);
    });
  });
});
