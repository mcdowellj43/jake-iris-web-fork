# Threat Hunting Dashboard - Setup & Configuration Guide

## Overview

The Threat Hunting Dashboard provides proactive threat detection capabilities by integrating IRIS with OpenSearch/Elasticsearch. This guide will walk you through the complete setup process.

## Prerequisites

- IRIS v2.4.22 or later
- OpenSearch or Elasticsearch cluster (v1.x or v2.x)
- Access to IRIS with administrative privileges
- Network connectivity from IRIS to OpenSearch

---

## Installation Steps

### Step 1: Database Migration

Apply the database migration to create the threat hunting tables:

```bash
# Navigate to the IRIS application directory
cd /path/to/iris/source

# Run the database migration
alembic -c app/alembic.ini upgrade head
```

**Expected Output:**
```
INFO  [alembic.runtime.migration] Running upgrade ff917e2ab02e -> 1a2b3c4d5e6f, Add threat hunting tables
```

**Tables Created:**
- `threat_hunting_queries` - Stores query definitions
- `threat_hunting_results` - Stores execution results
- `threat_hunting_artifacts` - Stores exported artifacts
- `threat_hunting_schedules` - Stores scheduled queries

### Step 2: Restart IRIS

Restart the IRIS application to load the new blueprint:

```bash
# For Docker deployment
docker-compose restart app worker

# For Kubernetes deployment
kubectl rollout restart deployment/iris-app
kubectl rollout restart deployment/iris-worker
```

### Step 3: Configure OpenSearch Integration

#### Option A: Via Web UI (Recommended)

1. **Log in to IRIS** as an administrator

2. **Navigate to Manage → Integrations**
   - URL: `https://your-iris-instance/manage/integrations`

3. **Configure OpenSearch**:
   - Scroll down to find **"OpenSearch"** in the integrations list
   - Click **"Configure"** or **"Edit"**

4. **Enter Configuration Values**:

   | Field | Description | Example Value |
   |-------|-------------|---------------|
   | **Enabled** | Enable/disable integration | ☑️ Checked |
   | **Base URL** | OpenSearch endpoint URL | `https://opensearch.example.com:9200` |
   | **API Key** | API key for authentication (optional) | `<your-api-key>` |
   | **Username** | Username for basic auth (optional) | `admin` |
   | **Password** | Password for basic auth (optional) | `<your-password>` |
   | **Verify SSL** | Verify SSL certificates | ☑️ Checked (uncheck for self-signed) |
   | **Timeout** | Request timeout in seconds | `60` |
   | **Default Index** | Default index pattern to search | `*` or `winlogbeat-*,sysmon-*` |

5. **Test Connection**:
   - Click **"Test Connection"** button
   - Verify you see: ✅ "Connection successful"
   - Check cluster name and version are displayed

6. **Save Configuration**:
   - Click **"Save"**
   - Confirm settings are saved

#### Option B: Via Database (Advanced)

If you prefer to configure via database directly:

```sql
-- Insert OpenSearch configuration
INSERT INTO integration_config (integration_type, enabled, config_data, created_by, updated_by)
VALUES (
  'opensearch',
  true,
  '{
    "base_url": "https://opensearch.example.com:9200",
    "api_key": "",
    "username": "admin",
    "password": "your-password-here",
    "verify_ssl": true,
    "timeout": 60,
    "default_index": "*"
  }'::jsonb,
  1,
  1
)
ON CONFLICT (integration_type) DO UPDATE
SET
  enabled = EXCLUDED.enabled,
  config_data = EXCLUDED.config_data,
  updated_by = EXCLUDED.updated_by;
```

---

## Configuration Details

### Authentication Methods

The OpenSearch handler supports two authentication methods:

#### 1. API Key Authentication (Recommended)

```json
{
  "enabled": true,
  "base_url": "https://opensearch.example.com:9200",
  "api_key": "base64-encoded-api-key",
  "verify_ssl": true,
  "timeout": 60,
  "default_index": "*"
}
```

**How to generate an API key in OpenSearch:**

```bash
# Using OpenSearch Security Plugin
curl -X POST "https://opensearch.example.com:9200/_plugins/_security/api/generatekey" \
  -u admin:admin \
  -H 'Content-Type: application/json' \
  -d '{"name":"iris-threat-hunting","cluster_permissions":["cluster:admin/opendistro/reports/menu/download"]}'
```

#### 2. Basic Authentication

```json
{
  "enabled": true,
  "base_url": "https://opensearch.example.com:9200",
  "username": "iris-user",
  "password": "secure-password",
  "verify_ssl": true,
  "timeout": 60,
  "default_index": "*"
}
```

**Note:** If both `api_key` and `username/password` are provided, API key takes precedence.

### SSL/TLS Configuration

#### For Production (SSL Verification Enabled)

```json
{
  "verify_ssl": true,
  "base_url": "https://opensearch.example.com:9200"
}
```

- Requires valid SSL certificate
- Certificate must be signed by a trusted CA
- Recommended for production environments

#### For Development/Self-Signed Certificates

```json
{
  "verify_ssl": false,
  "base_url": "https://opensearch.example.com:9200"
}
```

- **Warning:** Only use in development/testing
- Disables SSL certificate validation
- Not recommended for production

### Index Pattern Configuration

The `default_index` setting determines which indices are searched:

```json
// Search all indices
{"default_index": "*"}

// Search specific index patterns
{"default_index": "winlogbeat-*,sysmon-*"}

// Search multiple specific indices
{"default_index": "security-logs-*,firewall-logs-*"}

// Search date-based indices
{"default_index": "logs-2025-*"}
```

**Recommendation:** Use specific index patterns to improve query performance.

---

## Accessing the Threat Hunting Dashboard

1. **Navigate to Threat Hunting**:
   - URL: `https://your-iris-instance/threat-hunting`
   - Or click **"Threat Hunting"** in the navigation menu

2. **Verify Dashboard Loads**:
   - You should see 4 statistics cards at the top
   - Query library on the left (21 pre-built queries)
   - Execution panel in the center
   - Results panel on the right

3. **Test the Connection**:
   - Click **"Test Connection"** button in the top-right
   - Should display: ✅ "Connected successfully to [cluster-name] (v[version]) - Response time: XXXms"

---

## Using the Threat Hunting Dashboard

### Executing Your First Query

1. **Select a Query**:
   - Browse the query library on the left
   - Click on a query (e.g., "Brute Force Attack Detection")

2. **Configure Execution**:
   - **Time Range**: Select how far back to search (default: 24h)
   - **Index Pattern**: Leave empty for default, or specify (e.g., `winlogbeat-*`)
   - **Case Association**: Optionally enter a case ID

3. **Execute**:
   - Click **"Execute Hunt"**
   - Wait for results (typically 1-5 seconds)

4. **Review Results**:
   - **Hit Count**: Number of events matched
   - **Execution Time**: Query performance
   - **Aggregations**: Grouped results (e.g., by source IP, user)
   - **Sample Events**: First 20 matching events with details

5. **Add to Case** (Optional):
   - Click **"Add to Case"** button
   - Enter case ID
   - Results will be added as a formatted case note

### Query Categories

The dashboard includes 21 pre-built detection queries across 8 categories:

1. **Email Compromise** (2 queries)
   - New inbox rules
   - External email forwarding

2. **Authentication Attacks** (2 queries)
   - Brute force detection
   - Password spray detection

3. **Credential Theft** (3 queries)
   - LSASS memory dumping
   - Mimikatz usage
   - SAM database extraction

4. **Lateral Movement** (3 queries)
   - PsExec detection
   - WMI/WmiExec detection
   - Suspicious RDP

5. **Privilege Escalation** (3 queries)
   - Token manipulation
   - UAC bypass
   - Scheduled task privesc

6. **Persistence** (3 queries)
   - Service installation
   - Scheduled task creation
   - Registry run keys

7. **Data Exfiltration** (3 queries)
   - Mass file encryption
   - Mass file compression
   - Large data uploads

8. **Backup Tampering** (3 queries)
   - VSS deletion
   - Backup deletion
   - Backup service tampering

---

## Troubleshooting

### Connection Issues

#### Error: "Could not connect to OpenSearch"

**Possible Causes:**
1. OpenSearch is not running
2. Network connectivity issues
3. Firewall blocking connection
4. Incorrect base URL

**Solutions:**
```bash
# Test connectivity from IRIS container
docker exec -it iris-app curl -k https://opensearch.example.com:9200

# Check firewall rules
# Ensure port 9200 (or your OpenSearch port) is accessible

# Verify OpenSearch is running
curl -k https://opensearch.example.com:9200
```

#### Error: "SSL certificate verification failed"

**Solutions:**
1. Add your CA certificate to IRIS trusted store
2. Or disable SSL verification (development only):
   ```json
   {"verify_ssl": false}
   ```

#### Error: "Authentication failed"

**Possible Causes:**
1. Invalid API key
2. Wrong username/password
3. Account locked/expired

**Solutions:**
```bash
# Test credentials directly
curl -u username:password https://opensearch.example.com:9200

# Or with API key
curl -H "Authorization: ApiKey YOUR_KEY" https://opensearch.example.com:9200
```

### Query Execution Issues

#### Error: "Query execution timeout"

**Solutions:**
1. Increase timeout value in configuration:
   ```json
   {"timeout": 120}
   ```
2. Reduce time range (e.g., from 30d to 7d)
3. Use more specific index patterns
4. Optimize OpenSearch cluster performance

#### Error: "Index not found"

**Solutions:**
1. Verify index exists in OpenSearch:
   ```bash
   curl https://opensearch.example.com:9200/_cat/indices
   ```
2. Update `default_index` configuration
3. Or specify index pattern when executing query

#### No Results Found (But You Expect Results)

**Troubleshooting:**
1. **Check Index Pattern**: Ensure correct indices are being searched
2. **Verify Time Range**: Events might be outside selected time range
3. **Check Field Mappings**: Ensure ECS field names match your logs
4. **Test in OpenSearch Directly**:
   ```bash
   curl -X POST "https://opensearch.example.com:9200/_search" \
     -H 'Content-Type: application/json' \
     -d '{
       "query": {
         "match_all": {}
       },
       "size": 1
     }'
   ```

### Performance Issues

#### Slow Query Execution

**Optimizations:**
1. **Use Specific Index Patterns**:
   - ❌ Bad: `"*"`
   - ✅ Good: `"winlogbeat-2025-01-*"`

2. **Reduce Time Range**:
   - Start with 1h or 4h for testing
   - Expand to 24h or 7d as needed

3. **Limit Result Size**:
   - Queries default to 1000 results
   - Only first 100 displayed in UI

4. **Add Index Shards**:
   ```bash
   # Check index settings
   curl https://opensearch.example.com:9200/your-index/_settings
   ```

5. **Enable Query Caching** in OpenSearch

---

## Field Mapping Requirements

The pre-built queries assume Elastic Common Schema (ECS) field names. If your logs use different field names, you'll need to customize the queries.

### Required Fields by Query Type

#### Windows Event Logs
- `event.code` - Event ID (e.g., 4625, 7045)
- `event.category` - Category (e.g., "authentication", "process")
- `event.outcome` - Result (e.g., "success", "failure")
- `host.name` - Hostname
- `user.name` - Username
- `source.ip` - Source IP address
- `@timestamp` - Event timestamp

#### Process Events (Sysmon)
- `process.name` - Process name
- `process.command_line` - Full command line
- `process.parent.name` - Parent process
- `file.path` - File path
- `winlog.event_data.*` - Windows event data fields

#### Network Events
- `destination.ip` - Destination IP
- `destination.domain` - Destination domain
- `network.bytes` - Bytes transferred
- `network.direction` - Traffic direction

### Customizing Queries for Your Field Names

If your logs use different field names, you can customize queries in:
`/source/app/blueprints/threat_hunting_queries.py`

Example:
```python
# Change from ECS field names
"process.name": "mimikatz.exe"

# To your custom field names
"ProcessName": "mimikatz.exe"
```

---

## Advanced Configuration

### Creating Custom Queries

You can add custom queries to the library by editing:
`/source/app/blueprints/threat_hunting_queries.py`

Example custom query:
```python
MY_CUSTOM_QUERY = {
    "query_name": "My Custom Detection",
    "description": "Detects custom suspicious activity",
    "mitre_attack": ["T1234.567"],
    "severity": "high",
    "query": {
        "bool": {
            "must": [
                {
                    "match": {
                        "event.code": "1234"
                    }
                },
                {
                    "wildcard": {
                        "process.command_line": "*suspicious*"
                    }
                }
            ]
        }
    },
    "aggregation": {
        "by_host": {
            "terms": {
                "field": "host.name.keyword",
                "size": 50
            }
        }
    },
    "time_range": "24h"
}

# Add to THREAT_HUNTING_QUERIES dictionary
THREAT_HUNTING_QUERIES["my_custom_query"] = MY_CUSTOM_QUERY

# Add to category
QUERY_CATEGORIES["Custom Detections"] = ["my_custom_query"]
```

### Scheduled Query Execution

The threat hunting framework supports scheduled queries (future enhancement):

```python
# Database schema already includes threat_hunting_schedules table
# Implementation pending in future release
```

---

## Security Considerations

### Access Control

The threat hunting dashboard requires the following IRIS permissions:
- `Permissions.search_across_cases` - To access dashboard and execute queries
- `Permissions.alerts_read` - To test OpenSearch connection
- `CaseAccessLevel.full_access` - To add results to cases

### OpenSearch Access

**Recommended OpenSearch Permissions:**
```json
{
  "cluster_permissions": [
    "cluster:monitor/health",
    "cluster:monitor/state"
  ],
  "index_permissions": [{
    "index_patterns": [
      "winlogbeat-*",
      "sysmon-*",
      "security-logs-*"
    ],
    "allowed_actions": [
      "indices:data/read/search",
      "indices:data/read/get",
      "indices:admin/mappings/get"
    ]
  }]
}
```

**Security Best Practices:**
1. Use API key authentication (not username/password)
2. Grant read-only access to IRIS service account
3. Limit index patterns to necessary indices only
4. Enable SSL/TLS verification in production
5. Rotate API keys regularly
6. Monitor OpenSearch access logs

### Data Privacy

The threat hunting dashboard will:
- Store query results in IRIS database
- Include sample events (first 20) in results
- Allow export of results to case notes

**Considerations:**
- Results may contain sensitive data (usernames, IPs, filenames)
- Configure appropriate retention policies
- Ensure compliance with data protection regulations
- Review results before adding to cases

---

## Maintenance

### Database Cleanup

Query results are stored indefinitely. To clean up old results:

```sql
-- Delete results older than 90 days
DELETE FROM threat_hunting_results
WHERE created_at < NOW() - INTERVAL '90 days';

-- Delete orphaned artifacts
DELETE FROM threat_hunting_artifacts
WHERE result_id NOT IN (SELECT result_id FROM threat_hunting_results);
```

### Monitoring

Monitor threat hunting usage:

```sql
-- Query execution statistics
SELECT
  COUNT(*) as total_executions,
  AVG(hit_count) as avg_hits,
  AVG(execution_time_ms) as avg_exec_time_ms
FROM threat_hunting_results
WHERE created_at > NOW() - INTERVAL '7 days';

-- Most executed queries
SELECT
  query_id,
  COUNT(*) as execution_count,
  AVG(hit_count) as avg_hits,
  MAX(created_at) as last_executed
FROM threat_hunting_results
GROUP BY query_id
ORDER BY execution_count DESC
LIMIT 10;

-- Failed executions
SELECT
  query_id,
  error_message,
  COUNT(*) as failure_count
FROM threat_hunting_results
WHERE status = 'failed'
AND created_at > NOW() - INTERVAL '7 days'
GROUP BY query_id, error_message;
```

---

## Support & Resources

### Documentation
- **IRIS Documentation**: https://docs.dfir-iris.org
- **OpenSearch Documentation**: https://opensearch.org/docs/latest/
- **ECS Field Reference**: https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html
- **MITRE ATT&CK**: https://attack.mitre.org/

### Logs

Check IRIS application logs for threat hunting errors:

```bash
# Docker deployment
docker logs iris-app | grep "threat_hunting"

# Kubernetes deployment
kubectl logs deployment/iris-app | grep "threat_hunting"

# Check OpenSearch handler logs
grep "OpenSearchHandler" /var/log/iris/app.log
```

### Getting Help

If you encounter issues:
1. Check this setup guide
2. Review IRIS application logs
3. Test OpenSearch connection independently
4. Verify database migration completed
5. Open an issue on GitHub: https://github.com/dfir-iris/iris-web/issues

---

## Summary

**Configuration Location**:
- Web UI: `Manage → Integrations → OpenSearch`
- Database: `integration_config` table

**Key Configuration Fields**:
```json
{
  "enabled": true,
  "base_url": "https://opensearch.example.com:9200",
  "api_key": "your-api-key-here",
  "verify_ssl": true,
  "timeout": 60,
  "default_index": "winlogbeat-*,sysmon-*"
}
```

**Access Dashboard**: `https://your-iris-instance/threat-hunting`

**Queries Available**: 21 pre-built detection queries across 8 categories

**MITRE ATT&CK Coverage**: 21 techniques across 10 tactics

For questions or issues, please refer to the IRIS documentation or open a GitHub issue.
