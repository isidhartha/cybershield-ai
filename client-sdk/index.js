"use strict";
class CyberShieldClient {
  constructor(o={}) { this.host=o.host||"http://localhost:8000"; this.timeout=o.timeout||120000; }
  async _req(m,p,b) {
    const c=new AbortController(),t=setTimeout(()=>c.abort(),this.timeout);
    try {
      const r=await fetch(`${this.host}${p}`,{method:m,headers:{"Content-Type":"application/json"},body:b?JSON.stringify(b):undefined,signal:c.signal});
      if(!r.ok) throw new Error(`CyberShield API ${r.status}`);
      return r.json();
    } finally { clearTimeout(t); }
  }
  scanSecrets(code,filename="") { return this._req("POST","/api/v1/scan/secrets",{code,filename}); }
  scanCode(code,language="") { return this._req("POST","/api/v1/scan/code",{code,language}); }
  scanDependencies(manifest,ecosystem="pip") { return this._req("POST","/api/v1/scan/dependencies",{manifest,ecosystem}); }
  scanFull(code,options={}) { return this._req("POST","/api/v1/scan/full",{code,...options}); }
  aiReview(code,context="") { return this._req("POST","/api/v1/ai/review",{code,context}); }
  generateReport(scanId) { return this._req("POST","/api/v1/report/generate",{scan_id:scanId}); }
  health() { return this._req("GET","/health",null); }
}
module.exports=CyberShieldClient;
