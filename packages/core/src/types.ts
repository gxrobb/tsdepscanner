export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'unknown';
export type Confidence = 'high' | 'medium' | 'low' | 'unknown';
export type KnownSeverity = Exclude<Severity, 'unknown'>;
export type SeveritySource =
  | 'osv_cvss'
  | 'osv_label'
  | 'osv_detail_cvss'
  | 'osv_detail_label'
  | 'alias_cvss'
  | 'ghsa_cvss'
  | 'ghsa_label'
  | 'policy_override'
  | 'unknown';
export type UnknownReason = 'missing_score' | 'lookup_failed';
export type EvidenceMode = 'none' | 'imports';

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
  severitySource: SeveritySource;
  unknownReason?: UnknownReason;
  modified?: string;
  references?: string[];
  fixedVersion?: string;
}

export interface Finding {
  packageName: string;
  version: string;
  direct: boolean;
  severity: Severity;
  severitySource: SeveritySource;
  unknownReason?: UnknownReason;
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
  unknownAs: Severity;
  refreshCache: boolean;
  osvUrl?: string;
  enableNetworkFallbacks?: boolean;
  evidenceMode?: EvidenceMode;
}

export interface DbUpdateOptions {
  projectPath: string;
  outDir: string;
  refreshCache: boolean;
  osvUrl?: string;
  enableNetworkFallbacks?: boolean;
}

export interface DbUpdateReport {
  projectPath: string;
  generatedAt: string;
  dependencyCount: number;
  queriedCount: number;
  bySource: {
    osv: number;
    cache: number;
    unknown: number;
  };
}
