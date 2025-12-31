import React, { useState, useMemo } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faCopy, faCheck, faPlus, faTrash, faEdit, faFileAlt, faDownload, faListUl, faSave } from '@fortawesome/free-solid-svg-icons';
import type { ReportGeneratorData, ReportFinding, ReportSeverity, ReportTemplate, ReportFormat } from './tool-types';

type Props = {
  data: ReportGeneratorData | undefined;
  onChange: (data: ReportGeneratorData) => void;
};

const SEVERITY_INFO: Record<ReportSeverity, { label: string; color: string; score: string }> = {
  critical: { label: 'Critical', color: 'bg-red-600 text-white', score: '9.0-10.0' },
  high: { label: 'High', color: 'bg-orange-500 text-white', score: '7.0-8.9' },
  medium: { label: 'Medium', color: 'bg-yellow-500 text-black', score: '4.0-6.9' },
  low: { label: 'Low', color: 'bg-blue-500 text-white', score: '0.1-3.9' },
  info: { label: 'Info', color: 'bg-gray-500 text-white', score: '0.0' }
};

const TEMPLATE_INFO: Record<ReportTemplate, { label: string; description: string }> = {
  executive: { label: 'Executive Summary', description: 'High-level overview for stakeholders' },
  technical: { label: 'Technical Report', description: 'Detailed technical findings' },
  compliance: { label: 'Compliance Report', description: 'Regulatory compliance format' },
  pentest: { label: 'Pentest Report', description: 'Full penetration test report' },
  bugbounty: { label: 'Bug Bounty', description: 'Bug bounty submission format' }
};

const CATEGORIES = [
  'Injection', 'Authentication', 'Session Management', 'Access Control',
  'Cryptographic', 'Information Disclosure', 'XSS', 'CSRF', 'Configuration',
  'Business Logic', 'Input Validation', 'API Security', 'Other'
];

const CWE_DATABASE: Record<string, string> = {
  'Injection': 'CWE-74',
  'SQL Injection': 'CWE-89',
  'XSS': 'CWE-79',
  'CSRF': 'CWE-352',
  'Authentication': 'CWE-287',
  'Session Management': 'CWE-384',
  'Access Control': 'CWE-284',
  'Cryptographic': 'CWE-327',
  'Information Disclosure': 'CWE-200',
  'Configuration': 'CWE-16',
  'Input Validation': 'CWE-20',
  'API Security': 'CWE-285',
  'SSRF': 'CWE-918',
  'XXE': 'CWE-611',
  'Deserialization': 'CWE-502',
  'Path Traversal': 'CWE-22',
  'Command Injection': 'CWE-78',
  'SSTI': 'CWE-1336',
  'Open Redirect': 'CWE-601'
};

const generateId = () => Math.random().toString(36).substring(2, 9);

const ReportGenerator: React.FC<Props> = ({ data, onChange }) => {
  const projectName = data?.projectName ?? '';
  const targetUrl = data?.targetUrl ?? '';
  const tester = data?.tester ?? '';
  const date = data?.date ?? new Date().toISOString().split('T')[0];
  const findings = data?.findings ?? [];
  const selectedTemplate = data?.selectedTemplate ?? 'pentest';
  const outputFormat = data?.outputFormat ?? 'markdown';
  const activeTab = data?.activeTab ?? 'findings';
  const editingFindingId = data?.editingFindingId ?? null;

  const [copied, setCopied] = useState(false);
  const [newFinding, setNewFinding] = useState<Partial<ReportFinding>>({
    title: '',
    severity: 'medium',
    category: 'Other',
    description: '',
    impact: '',
    remediation: ''
  });

  const sortedFindings = useMemo(() => {
    const order: Record<ReportSeverity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    return [...findings].sort((a, b) => order[a.severity] - order[b.severity]);
  }, [findings]);

  const stats = useMemo(() => {
    const counts: Record<ReportSeverity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    findings.forEach(f => counts[f.severity]++);
    return counts;
  }, [findings]);

  const addFinding = () => {
    if (!newFinding.title || !newFinding.description) return;

    const finding: ReportFinding = {
      id: generateId(),
      title: newFinding.title,
      severity: newFinding.severity as ReportSeverity,
      category: newFinding.category || 'Other',
      description: newFinding.description,
      impact: newFinding.impact,
      remediation: newFinding.remediation,
      cwe: CWE_DATABASE[newFinding.category || ''] || CWE_DATABASE[newFinding.title || '']
    };

    onChange({
      ...data,
      findings: [...findings, finding]
    });

    setNewFinding({
      title: '',
      severity: 'medium',
      category: 'Other',
      description: '',
      impact: '',
      remediation: ''
    });
  };

  const removeFinding = (id: string) => {
    onChange({
      ...data,
      findings: findings.filter(f => f.id !== id)
    });
  };

  const generateReport = (): string => {
    const now = new Date().toLocaleDateString();

    switch (selectedTemplate) {
      case 'executive':
        return generateExecutiveReport();
      case 'technical':
        return generateTechnicalReport();
      case 'bugbounty':
        return generateBugBountyReport();
      case 'compliance':
        return generateComplianceReport();
      case 'pentest':
      default:
        return generatePentestReport();
    }
  };

  const generateExecutiveReport = (): string => {
    return `# Executive Security Summary

## Project Overview
- **Project:** ${projectName || 'Security Assessment'}
- **Target:** ${targetUrl || 'N/A'}
- **Date:** ${date}
- **Assessor:** ${tester || 'Security Team'}

## Risk Summary

| Severity | Count |
|----------|-------|
| Critical | ${stats.critical} |
| High | ${stats.high} |
| Medium | ${stats.medium} |
| Low | ${stats.low} |
| Informational | ${stats.info} |

**Total Findings:** ${findings.length}

## Key Findings

${sortedFindings.slice(0, 5).map(f => `- **[${f.severity.toUpperCase()}]** ${f.title}`).join('\n')}

## Recommendations

The assessment identified ${findings.length} security issues. Immediate attention should be given to the ${stats.critical + stats.high} critical and high severity findings.

---
*Report generated by XCalibr*`;
  };

  const generateTechnicalReport = (): string => {
    return `# Technical Security Assessment Report

## Assessment Details
- **Project:** ${projectName || 'Security Assessment'}
- **Target:** ${targetUrl || 'N/A'}
- **Date:** ${date}
- **Assessor:** ${tester || 'Security Team'}

## Findings Summary

| Severity | Count |
|----------|-------|
| Critical | ${stats.critical} |
| High | ${stats.high} |
| Medium | ${stats.medium} |
| Low | ${stats.low} |
| Info | ${stats.info} |

---

## Detailed Findings

${sortedFindings.map((f, i) => `### ${i + 1}. ${f.title}

**Severity:** ${f.severity.toUpperCase()} ${f.cvss ? `(CVSS: ${f.cvss})` : ''}
**Category:** ${f.category}
${f.cwe ? `**CWE:** ${f.cwe}` : ''}

#### Description
${f.description}

${f.impact ? `#### Impact\n${f.impact}` : ''}

${f.evidence ? `#### Evidence\n\`\`\`\n${f.evidence}\n\`\`\`` : ''}

${f.remediation ? `#### Remediation\n${f.remediation}` : ''}

---
`).join('\n')}

*Report generated by XCalibr*`;
  };

  const generateBugBountyReport = (): string => {
    const finding = sortedFindings[0];
    if (!finding) return '# No findings to report';

    return `## Summary
${finding.title}

## Severity
${finding.severity.toUpperCase()}${finding.cvss ? ` (CVSS: ${finding.cvss})` : ''}

## Description
${finding.description}

## Steps to Reproduce
1. Navigate to ${targetUrl || '[target URL]'}
2. [Add reproduction steps]

${finding.impact ? `## Impact\n${finding.impact}` : ''}

${finding.evidence ? `## Proof of Concept\n\`\`\`\n${finding.evidence}\n\`\`\`` : ''}

${finding.remediation ? `## Suggested Fix\n${finding.remediation}` : ''}

${finding.references?.length ? `## References\n${finding.references.map(r => `- ${r}`).join('\n')}` : ''}`;
  };

  const generateComplianceReport = (): string => {
    return `# Compliance Security Assessment

## Control Assessment Summary
- **Organization:** ${projectName || 'Organization'}
- **Scope:** ${targetUrl || 'N/A'}
- **Assessment Date:** ${date}
- **Assessor:** ${tester || 'Security Team'}

## Non-Compliance Summary

| Risk Level | Count | Status |
|------------|-------|--------|
| Critical | ${stats.critical} | ${stats.critical > 0 ? 'Non-Compliant' : 'Compliant'} |
| High | ${stats.high} | ${stats.high > 0 ? 'Needs Attention' : 'Compliant'} |
| Medium | ${stats.medium} | ${stats.medium > 0 ? 'Needs Improvement' : 'Compliant'} |
| Low | ${stats.low} | ${stats.low > 0 ? 'Minor Issues' : 'Compliant'} |

## Findings Detail

${sortedFindings.map((f, i) => `### Finding ${i + 1}: ${f.title}

- **Risk Level:** ${f.severity.toUpperCase()}
- **Control Category:** ${f.category}
${f.cwe ? `- **Related CWE:** ${f.cwe}` : ''}
- **Status:** Non-Compliant

**Observation:** ${f.description}

${f.remediation ? `**Recommendation:** ${f.remediation}` : ''}

---
`).join('\n')}

*Compliance report generated by XCalibr*`;
  };

  const generatePentestReport = (): string => {
    return `# Penetration Test Report

## Engagement Overview

| Field | Value |
|-------|-------|
| Project | ${projectName || 'Penetration Test'} |
| Target | ${targetUrl || 'N/A'} |
| Test Date | ${date} |
| Tester | ${tester || 'Security Team'} |
| Report Date | ${new Date().toLocaleDateString()} |

## Executive Summary

This penetration test identified **${findings.length}** security vulnerabilities:
- **${stats.critical}** Critical
- **${stats.high}** High
- **${stats.medium}** Medium
- **${stats.low}** Low
- **${stats.info}** Informational

## Findings Overview

| # | Title | Severity | Category |
|---|-------|----------|----------|
${sortedFindings.map((f, i) => `| ${i + 1} | ${f.title} | ${f.severity} | ${f.category} |`).join('\n')}

---

## Detailed Findings

${sortedFindings.map((f, i) => `### ${i + 1}. ${f.title}

| Attribute | Value |
|-----------|-------|
| Severity | **${f.severity.toUpperCase()}** |
| Category | ${f.category} |
${f.cvss ? `| CVSS | ${f.cvss} |` : ''}
${f.cwe ? `| CWE | ${f.cwe} |` : ''}

#### Description
${f.description}

${f.impact ? `#### Impact\n${f.impact}` : ''}

${f.evidence ? `#### Evidence\n\`\`\`\n${f.evidence}\n\`\`\`` : ''}

${f.remediation ? `#### Remediation\n${f.remediation}` : ''}

---
`).join('\n')}

## Appendix

### Methodology
Standard web application penetration testing methodology was followed.

### Tools Used
- XCalibr Security Toolkit
- Manual Testing

---
*Report generated by XCalibr Security Toolkit*`;
  };

  const formatReport = (report: string): string => {
    switch (outputFormat) {
      case 'html':
        return `<!DOCTYPE html>
<html>
<head>
  <title>${projectName || 'Security Report'}</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 900px; margin: 0 auto; padding: 20px; }
    table { border-collapse: collapse; width: 100%; margin: 10px 0; }
    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
    th { background: #f5f5f5; }
    code { background: #f5f5f5; padding: 2px 4px; border-radius: 3px; }
    pre { background: #f5f5f5; padding: 10px; overflow-x: auto; }
    h1, h2, h3 { color: #333; }
  </style>
</head>
<body>
${report.replace(/^# (.+)$/gm, '<h1>$1</h1>')
        .replace(/^## (.+)$/gm, '<h2>$1</h2>')
        .replace(/^### (.+)$/gm, '<h3>$1</h3>')
        .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
        .replace(/\n/g, '<br>\n')}
</body>
</html>`;
      case 'json':
        return JSON.stringify({
          projectName,
          targetUrl,
          tester,
          date,
          summary: stats,
          findings: sortedFindings
        }, null, 2);
      case 'csv':
        return `Title,Severity,Category,CWE,Description,Impact,Remediation
${sortedFindings.map(f =>
  `"${f.title}","${f.severity}","${f.category}","${f.cwe || ''}","${f.description.replace(/"/g, '""')}","${(f.impact || '').replace(/"/g, '""')}","${(f.remediation || '').replace(/"/g, '""')}"`
).join('\n')}`;
      case 'markdown':
      default:
        return report;
    }
  };

  const generatedReport = formatReport(generateReport());

  const copyReport = () => {
    navigator.clipboard.writeText(generatedReport);
    setCopied(true);
    onChange({ ...data, generatedReport });
    setTimeout(() => setCopied(false), 2000);
  };

  const downloadReport = () => {
    const ext = outputFormat === 'html' ? 'html' : outputFormat === 'json' ? 'json' : outputFormat === 'csv' ? 'csv' : 'md';
    const blob = new Blob([generatedReport], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${projectName || 'security-report'}-${date}.${ext}`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="flex flex-col h-full text-xs">
      <div className="flex items-center justify-between mb-2">
        <div className="text-slate-200 font-medium">
          <FontAwesomeIcon icon={faFileAlt} className="w-3 h-3 mr-1" />
          Report Generator
        </div>
        <div className="flex items-center gap-1">
          {Object.entries(stats).filter(([_, c]) => c > 0).map(([sev, count]) => (
            <span key={sev} className={`px-1.5 py-0.5 rounded text-[8px] ${SEVERITY_INFO[sev as ReportSeverity].color}`}>
              {count}
            </span>
          ))}
        </div>
      </div>

      {/* Project Info */}
      <div className="grid grid-cols-2 gap-2 mb-2">
        <input
          type="text"
          value={projectName}
          onChange={(e) => onChange({ ...data, projectName: e.target.value })}
          placeholder="Project Name"
          className="rounded bg-slate-800 text-slate-200 text-[10px] px-2 py-1 border border-slate-700"
        />
        <input
          type="text"
          value={targetUrl}
          onChange={(e) => onChange({ ...data, targetUrl: e.target.value })}
          placeholder="Target URL"
          className="rounded bg-slate-800 text-slate-200 text-[10px] px-2 py-1 border border-slate-700"
        />
        <input
          type="text"
          value={tester}
          onChange={(e) => onChange({ ...data, tester: e.target.value })}
          placeholder="Tester Name"
          className="rounded bg-slate-800 text-slate-200 text-[10px] px-2 py-1 border border-slate-700"
        />
        <input
          type="date"
          value={date}
          onChange={(e) => onChange({ ...data, date: e.target.value })}
          className="rounded bg-slate-800 text-slate-200 text-[10px] px-2 py-1 border border-slate-700"
        />
      </div>

      {/* Tabs */}
      <div className="flex border-b border-slate-700 mb-2">
        {(['findings', 'generate', 'export'] as const).map(tab => (
          <button
            key={tab}
            onClick={() => onChange({ ...data, activeTab: tab })}
            className={`px-3 py-1.5 text-[10px] transition-colors ${
              activeTab === tab
                ? 'text-blue-400 border-b-2 border-blue-400'
                : 'text-slate-400 hover:text-slate-300'
            }`}
          >
            {tab === 'findings' && <><FontAwesomeIcon icon={faListUl} className="w-2.5 h-2.5 mr-1" />Findings ({findings.length})</>}
            {tab === 'generate' && <><FontAwesomeIcon icon={faFileAlt} className="w-2.5 h-2.5 mr-1" />Generate</>}
            {tab === 'export' && <><FontAwesomeIcon icon={faDownload} className="w-2.5 h-2.5 mr-1" />Export</>}
          </button>
        ))}
      </div>

      {/* Findings Tab */}
      {activeTab === 'findings' && (
        <div className="flex-1 flex flex-col min-h-0">
          {/* Add Finding Form */}
          <div className="rounded border border-slate-700 bg-slate-800/30 p-2 mb-2">
            <div className="text-[10px] text-slate-400 mb-2 flex items-center gap-1">
              <FontAwesomeIcon icon={faPlus} className="w-2.5 h-2.5" />
              Add Finding
            </div>
            <div className="grid grid-cols-2 gap-2 mb-2">
              <input
                type="text"
                value={newFinding.title || ''}
                onChange={(e) => setNewFinding({ ...newFinding, title: e.target.value })}
                placeholder="Finding Title"
                className="rounded bg-slate-800 text-slate-200 text-[10px] px-2 py-1 border border-slate-700 col-span-2"
              />
              <select
                value={newFinding.severity || 'medium'}
                onChange={(e) => setNewFinding({ ...newFinding, severity: e.target.value as ReportSeverity })}
                className="rounded bg-slate-800 text-slate-200 text-[10px] px-2 py-1 border border-slate-700"
              >
                {Object.entries(SEVERITY_INFO).map(([sev, info]) => (
                  <option key={sev} value={sev}>{info.label}</option>
                ))}
              </select>
              <select
                value={newFinding.category || 'Other'}
                onChange={(e) => setNewFinding({ ...newFinding, category: e.target.value })}
                className="rounded bg-slate-800 text-slate-200 text-[10px] px-2 py-1 border border-slate-700"
              >
                {CATEGORIES.map(cat => (
                  <option key={cat} value={cat}>{cat}</option>
                ))}
              </select>
            </div>
            <textarea
              value={newFinding.description || ''}
              onChange={(e) => setNewFinding({ ...newFinding, description: e.target.value })}
              placeholder="Description"
              className="w-full h-16 rounded bg-slate-800 text-slate-200 text-[10px] px-2 py-1 border border-slate-700 font-mono resize-none mb-2"
            />
            <div className="grid grid-cols-2 gap-2 mb-2">
              <textarea
                value={newFinding.impact || ''}
                onChange={(e) => setNewFinding({ ...newFinding, impact: e.target.value })}
                placeholder="Impact"
                className="h-12 rounded bg-slate-800 text-slate-200 text-[10px] px-2 py-1 border border-slate-700 resize-none"
              />
              <textarea
                value={newFinding.remediation || ''}
                onChange={(e) => setNewFinding({ ...newFinding, remediation: e.target.value })}
                placeholder="Remediation"
                className="h-12 rounded bg-slate-800 text-slate-200 text-[10px] px-2 py-1 border border-slate-700 resize-none"
              />
            </div>
            <button
              onClick={addFinding}
              disabled={!newFinding.title || !newFinding.description}
              className="w-full px-3 py-1.5 rounded bg-blue-600 text-white text-[10px] hover:bg-blue-700 disabled:opacity-50 flex items-center justify-center gap-1"
            >
              <FontAwesomeIcon icon={faPlus} className="w-2.5 h-2.5" />
              Add Finding
            </button>
          </div>

          {/* Findings List */}
          <div className="flex-1 overflow-y-auto space-y-1">
            {sortedFindings.map((finding) => (
              <div
                key={finding.id}
                className="rounded border border-slate-700 bg-slate-800/30 p-2"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className={`px-1.5 py-0.5 rounded text-[8px] ${SEVERITY_INFO[finding.severity].color}`}>
                      {finding.severity.toUpperCase()}
                    </span>
                    <span className="text-slate-200 text-[10px] font-medium">{finding.title}</span>
                  </div>
                  <button
                    onClick={() => removeFinding(finding.id)}
                    className="text-red-400 hover:text-red-300"
                  >
                    <FontAwesomeIcon icon={faTrash} className="w-2.5 h-2.5" />
                  </button>
                </div>
                <div className="text-[9px] text-slate-500 mt-1">
                  {finding.category} {finding.cwe && `| ${finding.cwe}`}
                </div>
                <div className="text-[9px] text-slate-400 mt-1 line-clamp-2">
                  {finding.description}
                </div>
              </div>
            ))}
            {findings.length === 0 && (
              <div className="text-center text-slate-500 text-[10px] py-4">
                No findings added yet. Add your first finding above.
              </div>
            )}
          </div>
        </div>
      )}

      {/* Generate Tab */}
      {activeTab === 'generate' && (
        <div className="flex-1 flex flex-col min-h-0">
          <div className="grid grid-cols-2 gap-2 mb-2">
            <div>
              <label className="text-[10px] text-slate-500 block mb-1">Template</label>
              <select
                value={selectedTemplate}
                onChange={(e) => onChange({ ...data, selectedTemplate: e.target.value as ReportTemplate })}
                className="w-full rounded bg-slate-800 text-slate-200 text-[10px] px-2 py-1 border border-slate-700"
              >
                {Object.entries(TEMPLATE_INFO).map(([key, info]) => (
                  <option key={key} value={key}>{info.label}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="text-[10px] text-slate-500 block mb-1">Format</label>
              <select
                value={outputFormat}
                onChange={(e) => onChange({ ...data, outputFormat: e.target.value as ReportFormat })}
                className="w-full rounded bg-slate-800 text-slate-200 text-[10px] px-2 py-1 border border-slate-700"
              >
                <option value="markdown">Markdown</option>
                <option value="html">HTML</option>
                <option value="json">JSON</option>
                <option value="csv">CSV</option>
              </select>
            </div>
          </div>

          <div className="text-[9px] text-slate-500 mb-2">
            {TEMPLATE_INFO[selectedTemplate].description}
          </div>

          <div className="flex-1 overflow-auto rounded border border-slate-700 bg-slate-900 p-2">
            <pre className="text-[9px] text-slate-300 font-mono whitespace-pre-wrap">
              {generatedReport}
            </pre>
          </div>
        </div>
      )}

      {/* Export Tab */}
      {activeTab === 'export' && (
        <div className="flex-1 flex flex-col">
          <div className="rounded border border-slate-700 bg-slate-800/30 p-3 mb-2">
            <div className="text-[10px] text-slate-300 mb-2">Export Options</div>
            <div className="grid grid-cols-2 gap-2">
              <button
                onClick={copyReport}
                className="px-3 py-2 rounded bg-blue-600 text-white text-[10px] hover:bg-blue-700 flex items-center justify-center gap-1"
              >
                <FontAwesomeIcon icon={copied ? faCheck : faCopy} className="w-3 h-3" />
                {copied ? 'Copied!' : 'Copy to Clipboard'}
              </button>
              <button
                onClick={downloadReport}
                className="px-3 py-2 rounded bg-green-600 text-white text-[10px] hover:bg-green-700 flex items-center justify-center gap-1"
              >
                <FontAwesomeIcon icon={faDownload} className="w-3 h-3" />
                Download File
              </button>
            </div>
          </div>

          <div className="rounded border border-slate-700 bg-slate-800/30 p-3 flex-1">
            <div className="text-[10px] text-slate-400 mb-2">Report Statistics</div>
            <div className="grid grid-cols-2 gap-2">
              <div className="text-[10px] text-slate-500">Total Findings:</div>
              <div className="text-[10px] text-slate-300">{findings.length}</div>
              <div className="text-[10px] text-slate-500">Template:</div>
              <div className="text-[10px] text-slate-300">{TEMPLATE_INFO[selectedTemplate].label}</div>
              <div className="text-[10px] text-slate-500">Format:</div>
              <div className="text-[10px] text-slate-300">{outputFormat.toUpperCase()}</div>
              <div className="text-[10px] text-slate-500">Generated:</div>
              <div className="text-[10px] text-slate-300">{new Date().toLocaleString()}</div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export class ReportGeneratorTool {
  static Component = ReportGenerator;
}
