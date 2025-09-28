# IOC Enrichment Profiles Implementation Guide

This guide describes how to implement three initial IOC enrichment profiles (**IP-basic**, **Domain-basic**, **Hash-basic**) inside IRIS.  
The goal is to let SOC analysts run one-click enrichment jobs directly from the **IOC tab** in a case, with results written into Notes and raw data stored as artifacts.

---

## 🎯 Goals

- Analysts can trigger enrichment jobs directly from the **IOC tab**.  
- Each job runs a **profile** (bundle of enrichment sources).  
- Results are normalized, scored, and written to a **Markdown Note** in the case.  
- Raw JSON outputs are stored as **artifacts**.  
- Jobs are **idempotent**: re-running the same IOC updates the same note (new block is prepended).  
- RBAC controls access to deeper profiles; caching protects API quotas.

---

## 1. Profiles

Profiles are defined in YAML for flexibility. Each maps an IOC type to a set of enrichment sources.

### IP-basic
- **Purpose:** Quick IP risk context.  
- **Sources:**
  - AbuseIPDB – IP reputation and abuse categories  
  - GreyNoise (community) – scanner vs targeted traffic  
  - Cisco Talos – IP reputation  
  - RDAP/Whois – ownership, ASN, registrar  
  - GeoIP Lite – geolocation and ASN  

### Domain-basic
- **Purpose:** Spot phishing and infrastructure risks.  
- **Sources:**
  - AlienVault OTX – community threat pulses  
  - Cisco Talos – domain reputation  
  - Whois – registrar and creation date  
  - crt.sh – Certificate Transparency for subdomains  
  - URLhaus – malicious URL/domain feed  

### Hash-basic
- **Purpose:** Malware reputation and sandbox context.  
- **Sources:**
  - VirusTotal (free tier) – AV detections  
  - Hybrid Analysis – sandbox reports  
  - MalwareBazaar – malware community hashes  

### Example YAML
```yaml
profiles:
  IP-basic:
    ioc_type: ip
    description: Quick IP context
    sources: [abuseipdb, greynoise, talos, rdap, geoip]
    cache_ttl: 86400
    timeout_s: 6
  Domain-basic:
    ioc_type: domain
    description: Phishing/infrastructure context
    sources: [otx, talos, whois, crtsh, urlhaus]
    cache_ttl: 86400
    timeout_s: 8
  Hash-basic:
    ioc_type: hash
    description: Malware reputation
    sources: [virustotal, hybridanalysis, malwarebazaar]
    cache_ttl: 86400
    timeout_s: 8
```

---

## 2. Worker Implementation

### 2.1 Source modules
Each source is wrapped as a Python class:

```python
class AbuseIPDB:
    name = "abuseipdb"
    ioc_support = {"ip"}

    def fetch(self, ioc_type, ioc_value, timeout_s=6):
        # call API, parse response
        # return dict; on error, return {"_error": "msg"}
```

Repeat for all modules in the profiles.

---

### 2.2 Normalizer & risk score
Normalize raw results into a consistent structure:

```json
{
  "ioc": {"type":"ip","value":"45.76.200.1"},
  "summary": {
    "risk_score": 72,
    "classifications": ["Scanner","Brute-force"],
    "geo": "US",
    "asn": 20473
  },
  "sources": { ... },
  "errors": { ... }
}
```

**Scoring example:**
- +30 if AbuseIPDB confidence >75  
- +20 if Talos = “Poor/Malicious”  
- +15 if OTX pulse hit  
- −25 if GreyNoise = benign scanner  
- Clamp 0–100  

---

### 2.3 Markdown renderer
Generate clear Notes with:
- Header: IOC, timestamp, profile, risk score  
- Quick signals list  
- Collapsible raw details  
- Links to artifacts  

---

### 2.4 Artifacts
Save raw JSON output as artifacts:
- Named `<source>_<ioc>.json`  
- Tagged: `ioc`, `<ioc_type>`, `enrichment`, `<source>`  

---

### 2.5 Note upsert
Use GraphQL mutations to:
- **Find** note by case + title  
- If exists: prepend new block  
- Else: create new note titled `IOC Enrichment: <value>`  

---

## 3. Celery Job Outline

```python
@app.task(bind=True, autoretry_for=(Exception,), retry_backoff=True, max_retries=2)
def run_enrichment(self, case_id, ioc_type, ioc_value, profile_name):
    profile = PROFILES[profile_name]
    results = {}
    for src in profile["sources"]:
        results[src] = SOURCES[src].fetch(ioc_type, ioc_value)

    normalized = normalize(ioc_type, ioc_value, results)

    artifact_ids = []
    for name, data in results.items():
        artifact_ids.append(save_artifact(
            case_id,
            f"{name}_{ioc_value}.json",
            json.dumps(data),
            tags=["ioc", ioc_type, "enrichment", name]
        ))

    md = render_markdown(normalized, profile_name, artifact_ids)

    upsert_case_note_by_title(case_id, f"IOC Enrichment: {ioc_value}", md)
```

---

## 4. Frontend Integration (IOC Tab)

### Row Action
- In IOC grid, each row gets **“Run Enrichment” → [Available Profiles]**  
- Filtered by IOC type  

### Bulk Action
- Multi-select IOCs → **“Run Enrichment with Profile…”**  

### Feedback
- On click: toast **“Job queued”**  
- Job Drawer shows **Queued → Running → Done/Failed**  
- On Done: button **“Open Note”** → links to updated note  

### GraphQL Mutations
```graphql
mutation StartIocJob($caseId:ID!, $iocType:String!, $iocValue:String!, $profile:String!) {
  startIocJob(caseId:$caseId, iocType:$iocType, iocValue:$iocValue, profile:$profile) { jobId }
}

query JobStatus($jobId:ID!){
  jobStatus(jobId:$jobId){ status, noteId, error }
}
```

---

## 5. Expected User Experience

1. Analyst views case → **IOC tab**  
2. Right-click on IOC → **Run Enrichment → IP-basic**  
3. Toast confirms job queued; Job Drawer shows progress  
4. On completion, analyst clicks **Open Note**  
5. New Note appears:
   - Title: `IOC Enrichment: <value>`  
   - Summary risk score + quick context  
   - Collapsible details per source  
   - Raw JSON attached as artifacts  
6. Re-run later → note is updated with a new **Run block** at the top  

---

## 6. SOC Value

- **Tier-1:** Fast, consistent context without leaving IRIS  
- **Tier-2/3:** Deeper pivots using raw artifacts  
- **Managers:** Clear audit trail in Notes  
- **Organization:** Standardized enrichment flow, quotas managed by profiles  

---

## 7. Next Steps

- Add **URL-basic** and **Email-basic** profiles  
- Implement **“Re-run failed sources only”**  
- Support scheduled enrichments for VIPs or watchlists  
- Add **delta view** to show what changed since the last run  

---
