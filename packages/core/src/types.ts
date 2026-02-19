export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'unknown';
export type Confidence = 'high' | 'medium' | 'low' | 'unknown';

export interface DependencyNode {
  name: string;
  version: string;
  direct: boolean;
}

export interface ParsedLock {
  dependencies: DependencyNode[];
}

export interface OsvVulnerability {
  id: string;
  summary?: string;
  aliases?: string[];
  severity: Severity;
  modified?: string;
}

export interface Finding {
  packageName: string;
  version: string;
  direct: boolean;
  severity: Severity;
  confidence: Confidence;
  evidence: string[];
  vulnerabilities: OsvVulnerability[];
  source: 'osv' | 'cache' | 'unknown';
}

export interface ScanReport {
  targetPath: string;
  generatedAt: string;
  failOn: Severity | 'none';
  summary: {
    dependencyCount: number;
    scannedFiles: number;
    findingsCount: number;
    bySeverity: Record<Severity, number>;
    byConfidence: Record<Confidence, number>;
  };
  findings: Finding[];
}

export interface ScanOptions {
  projectPath: string;
  outDir: string;
  failOn: Severity | 'none';
  offline: boolean;
}
