import React from 'react';
import type { SslCertDecoderData, CertificateInfo } from './tool-types';

// Validate domain format
const isValidDomain = (domain: string): boolean => {
  const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$/;
  return domainRegex.test(domain);
};

// Format date for display
const formatDate = (dateString: string): string => {
  try {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric'
    });
  } catch {
    return dateString;
  }
};

// Get expiry status color
const getExpiryColor = (days: number): string => {
  if (days < 0) return 'xcalibr-text-red-400';
  if (days <= 30) return 'xcalibr-text-orange-400';
  if (days <= 90) return 'xcalibr-text-yellow-400';
  return 'xcalibr-text-green-400';
};

// Format expiry message
const formatExpiryMessage = (days: number): string => {
  if (days < 0) return `Expired ${Math.abs(days)} days ago`;
  if (days === 0) return 'Expires today';
  if (days === 1) return 'Expires tomorrow';
  return `${days} days remaining`;
};

const SslCertDecoderToolComponent = ({
  data,
  onChange,
  onDecode
}: {
  data: SslCertDecoderData | undefined;
  onChange: (next: SslCertDecoderData) => void;
  onDecode: (domain: string) => Promise<void>;
}) => {
  const domain = data?.domain ?? '';
  const loading = data?.loading ?? false;
  const certificate = data?.certificate;
  const fetchedAt = data?.fetchedAt;
  const error = data?.error;

  const handleDomainChange = (value: string) => {
    onChange({ ...data, domain: value.trim(), error: undefined });
  };

  const handleDecode = async () => {
    if (!domain || !isValidDomain(domain) || loading) return;
    await onDecode(domain);
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && domain && isValidDomain(domain)) {
      handleDecode();
    }
  };

  const handleClear = () => {
    onChange({});
  };

  const isDomainValid = domain.length > 0 && isValidDomain(domain);
  const hasResult = fetchedAt !== undefined;

  return (
    <div className="xcalibr-flex xcalibr-flex-col xcalibr-gap-3">
      <div className="xcalibr-flex xcalibr-gap-2">
        <input
          type="text"
          value={domain}
          onChange={(e) => handleDomainChange(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder="Enter domain (e.g., example.com)"
          className="xcalibr-flex-1 xcalibr-bg-[#1e1e1e] xcalibr-border xcalibr-border-[#333] xcalibr-rounded xcalibr-px-2 xcalibr-py-1 xcalibr-text-sm xcalibr-text-white"
          disabled={loading}
        />
        <button
          onClick={handleDecode}
          disabled={!isDomainValid || loading}
          className="xcalibr-bg-blue-600 xcalibr-text-white xcalibr-px-3 xcalibr-py-1 xcalibr-rounded xcalibr-text-sm hover:xcalibr-bg-blue-700 disabled:xcalibr-opacity-50 disabled:xcalibr-cursor-not-allowed"
        >
          {loading ? 'Fetching...' : 'Decode'}
        </button>
      </div>

      {domain && !isDomainValid && (
        <div className="xcalibr-text-xs xcalibr-text-yellow-400">
          Please enter a valid domain
        </div>
      )}

      {error && (
        <div className="xcalibr-bg-red-500/20 xcalibr-border xcalibr-border-red-500/50 xcalibr-rounded xcalibr-p-2 xcalibr-text-sm xcalibr-text-red-400">
          {error}
        </div>
      )}

      {hasResult && certificate && (
        <div className="xcalibr-flex xcalibr-flex-col xcalibr-gap-3">
          <div className="xcalibr-flex xcalibr-justify-between xcalibr-items-center">
            <span className="xcalibr-text-sm xcalibr-text-gray-400">
              Certificate Details
            </span>
            <button
              onClick={handleClear}
              className="xcalibr-text-xs xcalibr-text-gray-500 hover:xcalibr-text-gray-300"
            >
              Clear
            </button>
          </div>

          <CertificateDisplay certificate={certificate} />
        </div>
      )}

      {!hasResult && !loading && !error && (
        <div className="xcalibr-text-sm xcalibr-text-gray-400 xcalibr-text-center xcalibr-py-4">
          Enter a domain to decode its SSL certificate
        </div>
      )}
    </div>
  );
};

const CertificateDisplay = ({ certificate }: { certificate: CertificateInfo }) => {
  const [showSans, setShowSans] = React.useState(false);

  return (
    <div className="xcalibr-flex xcalibr-flex-col xcalibr-gap-2 xcalibr-max-h-80 xcalibr-overflow-y-auto">
      {/* Expiry Status */}
      <div className="xcalibr-bg-[#1e1e1e] xcalibr-border xcalibr-border-[#333] xcalibr-rounded xcalibr-p-2">
        <div className="xcalibr-flex xcalibr-justify-between xcalibr-items-center">
          <span className="xcalibr-text-xs xcalibr-text-gray-500">Status</span>
          <span className={`xcalibr-text-sm xcalibr-font-medium ${getExpiryColor(certificate.daysUntilExpiry)}`}>
            {certificate.isExpired ? 'EXPIRED' : 'VALID'}
          </span>
        </div>
        <div className={`xcalibr-text-xs xcalibr-mt-1 ${getExpiryColor(certificate.daysUntilExpiry)}`}>
          {formatExpiryMessage(certificate.daysUntilExpiry)}
        </div>
      </div>

      {/* Subject */}
      <div className="xcalibr-bg-[#1e1e1e] xcalibr-border xcalibr-border-[#333] xcalibr-rounded xcalibr-p-2">
        <div className="xcalibr-text-xs xcalibr-text-gray-500 xcalibr-mb-1">Subject</div>
        <div className="xcalibr-text-sm xcalibr-text-white">{certificate.subject.CN}</div>
        {certificate.subject.O && (
          <div className="xcalibr-text-xs xcalibr-text-gray-400">{certificate.subject.O}</div>
        )}
      </div>

      {/* Issuer */}
      <div className="xcalibr-bg-[#1e1e1e] xcalibr-border xcalibr-border-[#333] xcalibr-rounded xcalibr-p-2">
        <div className="xcalibr-text-xs xcalibr-text-gray-500 xcalibr-mb-1">Issuer</div>
        <div className="xcalibr-text-sm xcalibr-text-white">{certificate.issuer.CN}</div>
        {certificate.issuer.O && (
          <div className="xcalibr-text-xs xcalibr-text-gray-400">{certificate.issuer.O}</div>
        )}
      </div>

      {/* Validity Period */}
      <div className="xcalibr-bg-[#1e1e1e] xcalibr-border xcalibr-border-[#333] xcalibr-rounded xcalibr-p-2">
        <div className="xcalibr-text-xs xcalibr-text-gray-500 xcalibr-mb-1">Validity Period</div>
        <div className="xcalibr-flex xcalibr-justify-between xcalibr-text-xs">
          <span className="xcalibr-text-gray-400">From:</span>
          <span className="xcalibr-text-white">{formatDate(certificate.validFrom)}</span>
        </div>
        <div className="xcalibr-flex xcalibr-justify-between xcalibr-text-xs">
          <span className="xcalibr-text-gray-400">To:</span>
          <span className="xcalibr-text-white">{formatDate(certificate.validTo)}</span>
        </div>
      </div>

      {/* Technical Details */}
      <div className="xcalibr-bg-[#1e1e1e] xcalibr-border xcalibr-border-[#333] xcalibr-rounded xcalibr-p-2">
        <div className="xcalibr-text-xs xcalibr-text-gray-500 xcalibr-mb-1">Technical Details</div>
        <div className="xcalibr-flex xcalibr-flex-col xcalibr-gap-1 xcalibr-text-xs">
          <div className="xcalibr-flex xcalibr-justify-between">
            <span className="xcalibr-text-gray-400">Algorithm:</span>
            <span className="xcalibr-text-white">{certificate.signatureAlgorithm}</span>
          </div>
          {certificate.keySize && (
            <div className="xcalibr-flex xcalibr-justify-between">
              <span className="xcalibr-text-gray-400">Key Size:</span>
              <span className="xcalibr-text-white">{certificate.keySize} bits</span>
            </div>
          )}
          <div className="xcalibr-flex xcalibr-justify-between">
            <span className="xcalibr-text-gray-400">Serial:</span>
            <span className="xcalibr-text-white xcalibr-font-mono xcalibr-text-[10px]">
              {certificate.serialNumber.substring(0, 20)}...
            </span>
          </div>
        </div>
      </div>

      {/* Fingerprint */}
      <div className="xcalibr-bg-[#1e1e1e] xcalibr-border xcalibr-border-[#333] xcalibr-rounded xcalibr-p-2">
        <div className="xcalibr-text-xs xcalibr-text-gray-500 xcalibr-mb-1">Fingerprint (SHA-256)</div>
        <div className="xcalibr-text-[10px] xcalibr-text-white xcalibr-font-mono xcalibr-break-all">
          {certificate.fingerprint}
        </div>
      </div>

      {/* SANs */}
      {certificate.sans && certificate.sans.length > 0 && (
        <div className="xcalibr-bg-[#1e1e1e] xcalibr-border xcalibr-border-[#333] xcalibr-rounded xcalibr-overflow-hidden">
          <button
            onClick={() => setShowSans(!showSans)}
            className="xcalibr-w-full xcalibr-p-2 xcalibr-text-left xcalibr-flex xcalibr-justify-between xcalibr-items-center hover:xcalibr-bg-[#252525]"
          >
            <span className="xcalibr-text-xs xcalibr-text-gray-500">
              Subject Alt Names ({certificate.sans.length})
            </span>
            <span className="xcalibr-text-gray-500 xcalibr-text-xs">
              {showSans ? '▲' : '▼'}
            </span>
          </button>
          {showSans && (
            <div className="xcalibr-px-2 xcalibr-pb-2 xcalibr-border-t xcalibr-border-[#333]">
              <div className="xcalibr-flex xcalibr-flex-wrap xcalibr-gap-1 xcalibr-mt-2">
                {certificate.sans.map((san, i) => (
                  <span
                    key={i}
                    className="xcalibr-bg-[#333] xcalibr-px-1.5 xcalibr-py-0.5 xcalibr-rounded xcalibr-text-xs xcalibr-text-gray-300"
                  >
                    {san}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export class SslCertDecoderTool {
  static Component = SslCertDecoderToolComponent;
}
