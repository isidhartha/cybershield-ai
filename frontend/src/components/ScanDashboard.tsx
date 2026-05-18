import { useState, useRef } from "react";
import { Play, Upload, Code2, Loader2 } from "lucide-react";
import clsx from "clsx";

interface ScanDashboardProps {
  onScanComplete: (results: any) => void;
  scanType?: string;
}

const API_BASE = "/api/v1";

export function ScanDashboard({ onScanComplete, scanType = "code" }: ScanDashboardProps) {
  const [code, setCode] = useState("");
  const [language, setLanguage] = useState("python");
  const [isScanning, setIsScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [statusMsg, setStatusMsg] = useState("");
  const wsRef = useRef<WebSocket | null>(null);

  const LANGUAGES = ["python", "javascript", "typescript", "java", "go", "php", "ruby", "c", "cpp"];

  async function runScan() {
    if (!code.trim()) return;
    setIsScanning(true);
    setProgress(0);
    setStatusMsg("Connecting...");

    const scanId = crypto.randomUUID();
    const wsUrl = `${location.protocol === "https:" ? "wss:" : "ws:"}//${location.host}/ws/scan/${scanId}`;
    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;

    ws.onopen = () => {
      ws.send(JSON.stringify({
        code,
        language,
        scan_types: ["secrets", "code", "owasp"],
      }));
    };

    ws.onmessage = (evt) => {
      const data = JSON.parse(evt.data);
      setProgress(data.progress ?? 0);
      setStatusMsg(data.message ?? "");
      if (data.progress === 100) {
        onScanComplete(data.payload);
        setIsScanning(false);
      }
    };

    ws.onerror = async () => {
      // Fallback to REST
      setStatusMsg("Running scan...");
      try {
        const endpoint = scanType === "secrets"
          ? `${API_BASE}/scan/secrets`
          : scanType === "owasp"
          ? `${API_BASE}/scan/owasp`
          : `${API_BASE}/scan/code`;

        const resp = await fetch(endpoint, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ code, language }),
        });
        const result = await resp.json();
        onScanComplete(result);
      } catch (err) {
        setStatusMsg("Scan failed");
      } finally {
        setIsScanning(false);
        setProgress(100);
      }
    };

    ws.onclose = () => {
      setIsScanning(false);
    };
  }

  function handleFileUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => setCode(ev.target?.result as string);
    reader.readAsText(file);
  }

  return (
    <div className="glass-card p-6 space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-cyber-text flex items-center gap-2">
          <Code2 className="w-5 h-5 text-cyber-accent" />
          Code Input
        </h2>

        <div className="flex items-center gap-3">
          <select
            value={language}
            onChange={(e) => setLanguage(e.target.value)}
            className="bg-cyber-card border border-cyber-border text-cyber-text text-sm rounded-lg px-3 py-1.5 focus:outline-none focus:ring-1 focus:ring-cyber-accent"
          >
            {LANGUAGES.map((l) => (
              <option key={l} value={l}>{l}</option>
            ))}
          </select>

          <label className="btn-ghost cursor-pointer flex items-center gap-2 text-sm">
            <Upload className="w-4 h-4" />
            Upload
            <input type="file" className="hidden" onChange={handleFileUpload} accept=".py,.js,.ts,.java,.go,.php,.rb,.c,.cpp,.txt" />
          </label>
        </div>
      </div>

      <textarea
        value={code}
        onChange={(e) => setCode(e.target.value)}
        placeholder={`Paste ${language} code here for security analysis...`}
        className="w-full h-64 bg-cyber-bg border border-cyber-border rounded-lg p-4 text-sm font-mono text-cyber-text placeholder-cyber-muted focus:outline-none focus:ring-1 focus:ring-cyber-accent resize-y"
        spellCheck={false}
      />

      {isScanning && (
        <div className="space-y-2">
          <div className="flex items-center justify-between text-sm text-cyber-text-dim">
            <span className="flex items-center gap-2">
              <Loader2 className="w-4 h-4 animate-spin text-cyber-accent" />
              {statusMsg}
            </span>
            <span className="font-mono">{progress}%</span>
          </div>
          <div className="h-1.5 bg-cyber-card rounded-full overflow-hidden">
            <div
              className="h-full bg-gradient-to-r from-cyber-accent to-cyber-red transition-all duration-300 rounded-full"
              style={{ width: `${progress}%` }}
            />
          </div>
        </div>
      )}

      <button
        onClick={runScan}
        disabled={isScanning || !code.trim()}
        className={clsx(
          "w-full flex items-center justify-center gap-2 py-3 rounded-lg font-semibold text-sm transition-all",
          isScanning || !code.trim()
            ? "bg-cyber-card text-cyber-muted cursor-not-allowed"
            : "btn-primary"
        )}
      >
        {isScanning ? (
          <><Loader2 className="w-4 h-4 animate-spin" /> Scanning...</>
        ) : (
          <><Play className="w-4 h-4" /> Run Security Scan</>
        )}
      </button>
    </div>
  );
}
