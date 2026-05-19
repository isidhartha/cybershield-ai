export interface CyberShieldOptions { host?: string; timeout?: number; }
export interface Finding { severity: "critical"|"high"|"medium"|"low"; type: string; description: string; line?: number; remediation: string; }
export declare class CyberShieldClient {
  constructor(options?: CyberShieldOptions);
  scanSecrets(code: string, filename?: string): Promise<{ findings: Finding[] }>;
  scanCode(code: string, language?: string): Promise<{ findings: Finding[] }>;
  scanDependencies(manifest: string, ecosystem?: string): Promise<{ findings: Finding[] }>;
  scanFull(code: string, options?: object): Promise<{ findings: Finding[]; risk_score: number }>;
  aiReview(code: string, context?: string): Promise<{ review: string; findings: Finding[] }>;
  generateReport(scanId: string): Promise<{ report_url: string }>;
  health(): Promise<{ status: string }>;
}
export default CyberShieldClient;
