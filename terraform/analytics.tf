resource "aws_glue_catalog_database" "ot_telemetry" {
  count = var.enable_analytics ? 1 : 0
  name  = "ot_telemetry"
}

resource "aws_glue_catalog_table" "staged_telemetry" {
  count         = var.enable_analytics ? 1 : 0
  name          = "staged_telemetry"
  database_name = aws_glue_catalog_database.ot_telemetry[0].name

  table_type = "EXTERNAL_TABLE"

  parameters = {
    "classification"      = "parquet"
    "EXTERNAL"            = "TRUE"
    "parquet.compression" = "SNAPPY"
  }

  storage_descriptor {
    location      = "s3://${aws_s3_bucket.telemetry_buckets["staged"].bucket}/parsed/"
    input_format  = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat"

    ser_de_info {
      name                  = "parquet-serde"
      serialization_library = "org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe"
      parameters = {
        "serialization.format" = "1"
      }
    }

    columns {
      name = "timestamp"
      type = "string"
    }
    columns {
      name = "hostname"
      type = "string"
    }
    columns {
      name = "process"
      type = "string"
    }
    columns {
      name = "pid"
      type = "string"
    }
    columns {
      name = "message"
      type = "string"
    }
    columns {
      name = "ip"
      type = "string"
    }
    columns {
      name = "raw_line"
      type = "string"
    }
    columns {
      name = "error"
      type = "string"
    }
    columns {
      name = "alert_type"
      type = "string"
    }
    columns {
      name = "source_ip"
      type = "string"
    }
    columns {
      name = "dest_ip"
      type = "string"
    }
    columns {
      name = "mitre_id"
      type = "string"
    }
    columns {
      name = "description"
      type = "string"
    }
    columns {
      name = "flow_id"
      type = "bigint"
    }
    columns {
      name = "host"
      type = "string"
    }
    columns {
      name = "environment"
      type = "string"
    }
    columns {
      name = "event_type"
      type = "string"
    }
    columns {
      name = "src_ip"
      type = "string"
    }
    columns {
      name = "src_port"
      type = "int"
    }
    columns {
      name = "dest_port"
      type = "int"
    }
    columns {
      name = "proto"
      type = "string"
    }
    columns {
      name = "in_iface"
      type = "string"
    }
    columns {
      name = "alert"
      type = "string"
    }
    columns {
      name = "flow"
      type = "string"
    }
    columns {
      name = "detection_domain"
      type = "string"
    }
    columns {
      name = "event_name"
      type = "string"
    }
    columns {
      name = "event_source"
      type = "string"
    }
    columns {
      name = "user_arn"
      type = "string"
    }
    columns {
      name = "user_name"
      type = "string"
    }
    columns {
      name = "user_type"
      type = "string"
    }
    columns {
      name = "source_ip"
      type = "string"
    }
    columns {
      name = "mfa_used"
      type = "string"
    }
    columns {
      name = "error_code"
      type = "string"
    }
    columns {
      name = "account_id"
      type = "string"
    }
    columns {
      name = "guardduty_type"
      type = "string"
    }
    columns {
      name = "guardduty_severity"
      type = "string"
    }
    columns {
      name = "mitre_tactic"
      type = "string"
    }
    columns {
      name = "alert_reason"
      type = "string"
    }
    columns {
      name = "details"
      type = "string"
    }
    columns {
      name = "audit_id"
      type = "string"
    }
    columns {
      name = "request_received_timestamp"
      type = "string"
    }
    columns {
      name = "stage"
      type = "string"
    }
    columns {
      name = "verb"
      type = "string"
    }
    columns {
      name = "username"
      type = "string"
    }
    columns {
      name = "user_groups"
      type = "string"
    }
    columns {
      name = "namespace"
      type = "string"
    }
    columns {
      name = "resource"
      type = "string"
    }
    columns {
      name = "subresource"
      type = "string"
    }
    columns {
      name = "object_name"
      type = "string"
    }
    columns {
      name = "api_group"
      type = "string"
    }
    columns {
      name = "request_uri"
      type = "string"
    }
    columns {
      name = "request_object"
      type = "string"
    }
    columns {
      name = "container_image"
      type = "string"
    }
    columns {
      name = "workload"
      type = "string"
    }
    columns {
      name = "pod"
      type = "string"
    }
    columns {
      name = "container"
      type = "string"
    }
    columns {
      name = "process"
      type = "string"
    }
    columns {
      name = "command"
      type = "string"
    }
    columns {
      name = "file"
      type = "string"
    }
    columns {
      name = "user"
      type = "string"
    }
    columns {
      name = "falco_rule"
      type = "string"
    }
    columns {
      name = "falco_priority"
      type = "string"
    }
    columns {
      name = "severity"
      type = "string"
    }
  }

  partition_keys {
    name = "date"
    type = "string"
  }
  partition_keys {
    name = "source"
    type = "string"
  }
}

resource "aws_glue_catalog_table" "incident_reports" {
  count         = var.enable_analytics ? 1 : 0
  name          = "incident_reports"
  database_name = aws_glue_catalog_database.ot_telemetry[0].name

  table_type = "EXTERNAL_TABLE"

  parameters = {
    "classification" = "json"
    "EXTERNAL"       = "TRUE"
  }

  storage_descriptor {
    location      = "s3://${aws_s3_bucket.telemetry_buckets["reports"].bucket}/incidents/"
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      name                  = "json-serde"
      serialization_library = "org.openx.data.jsonserde.JsonSerDe"
    }

    columns {
      name = "incident_id"
      type = "string"
    }
    columns {
      name = "created_at"
      type = "string"
    }
    columns {
      name = "nist_phase"
      type = "string"
    }
    columns {
      name = "severity"
      type = "string"
    }
    columns {
      name = "detection_count"
      type = "int"
    }
    columns {
      name = "mitre_techniques"
      type = "array<string>"
    }
    columns {
      name = "mitre_techniques_by_framework"
      type = "struct<ics:array<string>,enterprise:array<string>>"
    }
    columns {
      name = "mitre_tactics"
      type = "array<string>"
    }
    columns {
      name = "detection_domains"
      type = "array<string>"
    }
    columns {
      name = "ot_detection_count"
      type = "int"
    }
    columns {
      name = "identity_detection_count"
      type = "int"
    }
    columns {
      name = "affected_assets"
      type = "struct<hosts:array<string>,source_ips:array<string>>"
    }
    columns {
      name = "timeline"
      type = "array<struct<incident_correlator:string,timestamp:string,severity:string,host:string,src_ip:string,alert_reason:string,details:string,original_key:string>>"
    }
    columns {
      name = "recommended_actions"
      type = "array<string>"
    }
  }
}

resource "aws_glue_catalog_table" "vulnerability_findings" {
  count         = var.enable_analytics ? 1 : 0
  name          = "vulnerability_findings"
  database_name = aws_glue_catalog_database.ot_telemetry[0].name

  table_type = "EXTERNAL_TABLE"

  parameters = {
    "classification"      = "parquet"
    "EXTERNAL"            = "TRUE"
    "parquet.compression" = "SNAPPY"
  }

  storage_descriptor {
    location      = "s3://${aws_s3_bucket.telemetry_buckets["staged"].bucket}/vulnerabilities/"
    input_format  = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat"

    ser_de_info {
      name                  = "parquet-serde"
      serialization_library = "org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe"
      parameters = {
        "serialization.format" = "1"
      }
    }

    columns {
      name = "finding_id"
      type = "string"
    }
    columns {
      name = "asset_vuln_key"
      type = "string"
    }
    columns {
      name = "scan_id"
      type = "string"
    }
    columns {
      name = "asset_id"
      type = "string"
    }
    columns {
      name = "hostname"
      type = "string"
    }
    columns {
      name = "ip"
      type = "string"
    }
    columns {
      name = "fqdn"
      type = "string"
    }
    columns {
      name = "os"
      type = "string"
    }
    columns {
      name = "plugin_id"
      type = "string"
    }
    columns {
      name = "title"
      type = "string"
    }
    columns {
      name = "description"
      type = "string"
    }
    columns {
      name = "solution"
      type = "string"
    }
    columns {
      name = "severity_source"
      type = "string"
    }
    columns {
      name = "cvss_score"
      type = "double"
    }
    columns {
      name = "cvss_vector"
      type = "string"
    }
    columns {
      name = "cvss_version"
      type = "string"
    }
    columns {
      name = "cvss_estimated"
      type = "boolean"
    }
    columns {
      name = "cve_ids"
      type = "string"
    }
    columns {
      name = "cwe_ids"
      type = "string"
    }
    columns {
      name = "exploit_available"
      type = "boolean"
    }
    columns {
      name = "patch_available"
      type = "boolean"
    }
    columns {
      name = "port"
      type = "string"
    }
    columns {
      name = "protocol"
      type = "string"
    }
    columns {
      name = "service"
      type = "string"
    }
    columns {
      name = "first_seen"
      type = "string"
    }
    columns {
      name = "last_seen"
      type = "string"
    }
    columns {
      name = "status"
      type = "string"
    }
    columns {
      name = "asset_criticality"
      type = "bigint"
    }
    columns {
      name = "criticality_source"
      type = "string"
    }
    columns {
      name = "epss_score"
      type = "double"
    }
    columns {
      name = "epss_percentile"
      type = "double"
    }
    columns {
      name = "epss_date"
      type = "string"
    }
    columns {
      name = "epss_missing"
      type = "boolean"
    }
    columns {
      name = "epss_stale"
      type = "boolean"
    }
    columns {
      name = "kev"
      type = "boolean"
    }
    columns {
      name = "kev_date"
      type = "string"
    }
    columns {
      name = "priority_score"
      type = "double"
    }
    columns {
      name = "priority_bucket"
      type = "string"
    }
    columns {
      name = "due_date"
      type = "string"
    }
    columns {
      name = "score_components"
      type = "string"
    }
    columns {
      name = "scoring_version"
      type = "string"
    }
    columns {
      name = "raw_ref"
      type = "string"
    }
    columns {
      name = "ingested_at"
      type = "string"
    }
  }

  partition_keys {
    name = "scan_date"
    type = "string"
  }
  partition_keys {
    name = "source"
    type = "string"
  }
}

resource "aws_athena_workgroup" "ot_analytics" {
  count = var.enable_analytics ? 1 : 0
  name  = "ot_analytics"

  configuration {
    result_configuration {
      output_location = "s3://${aws_s3_bucket.telemetry_buckets["reports"].bucket}/athena-results/"
    }
  }
}

resource "aws_athena_named_query" "ot_anomalies_over_time" {
  count     = var.enable_analytics ? 1 : 0
  name      = "ot_anomalies_over_time"
  workgroup = aws_athena_workgroup.ot_analytics[0].id
  database  = aws_glue_catalog_database.ot_telemetry[0].name
  query     = <<EOF
SELECT 
  date,
  source,
  count(*) as anomaly_count
FROM 
  staged_telemetry
WHERE 
  alert_type IN ('CROSS_ZONE_VIOLATION', 'UNAUTHORIZED_MODBUS_WRITE', 'OT_BRUTE_FORCE_SCAN')
  OR message LIKE '%anomaly%' OR message LIKE '%violation%'
GROUP BY 
  date, source
ORDER BY 
  date DESC, anomaly_count DESC;
EOF
}

resource "aws_athena_named_query" "top_noisy_hosts" {
  count     = var.enable_analytics ? 1 : 0
  name      = "top_noisy_hosts"
  workgroup = aws_athena_workgroup.ot_analytics[0].id
  database  = aws_glue_catalog_database.ot_telemetry[0].name
  query     = <<EOF
SELECT 
  COALESCE(hostname, host, 'unknown') as host_identifier,
  count(*) as log_count
FROM 
  staged_telemetry
GROUP BY 
  1
ORDER BY 
  log_count DESC
LIMIT 10;
EOF
}

resource "aws_athena_named_query" "scada_ttp_patterns" {
  count     = var.enable_analytics ? 1 : 0
  name      = "scada_ttp_patterns"
  workgroup = aws_athena_workgroup.ot_analytics[0].id
  database  = aws_glue_catalog_database.ot_telemetry[0].name
  query     = <<EOF
SELECT 
  timestamp,
  src_ip,
  dest_ip,
  json_extract_scalar(alert, '$.signature') as scada_signature,
  json_extract_scalar(alert, '$.category') as scada_category
FROM 
  staged_telemetry
WHERE 
  source = 'malcolm'
  AND json_extract_scalar(alert, '$.category') LIKE '%SCADA%'
ORDER BY 
  timestamp DESC;
EOF
}

resource "aws_athena_named_query" "identity_iam_changes" {
  count     = var.enable_analytics ? 1 : 0
  name      = "identity_iam_changes"
  workgroup = aws_athena_workgroup.ot_analytics[0].id
  database  = aws_glue_catalog_database.ot_telemetry[0].name
  query     = <<EOF
SELECT
  date,
  event_name,
  user_name,
  source_ip,
  count(*) AS changes
FROM staged_telemetry
WHERE source = 'cloudtrail'
  AND event_source = 'iam.amazonaws.com'
GROUP BY date, event_name, user_name, source_ip
ORDER BY changes DESC;
EOF
}

resource "aws_athena_named_query" "identity_console_logins" {
  count     = var.enable_analytics ? 1 : 0
  name      = "identity_console_logins"
  workgroup = aws_athena_workgroup.ot_analytics[0].id
  database  = aws_glue_catalog_database.ot_telemetry[0].name
  query     = <<EOF
SELECT
  date,
  user_name,
  source_ip,
  mfa_used,
  error_code,
  count(*) AS logins
FROM staged_telemetry
WHERE source = 'cloudtrail'
  AND event_name = 'ConsoleLogin'
GROUP BY date, user_name, source_ip, mfa_used, error_code
ORDER BY logins DESC;
EOF
}

resource "aws_athena_named_query" "guardduty_findings" {
  count     = var.enable_analytics ? 1 : 0
  name      = "guardduty_findings"
  workgroup = aws_athena_workgroup.ot_analytics[0].id
  database  = aws_glue_catalog_database.ot_telemetry[0].name
  query     = <<EOF
SELECT
  date,
  guardduty_type,
  guardduty_severity,
  count(*) AS findings
FROM staged_telemetry
WHERE source = 'guardduty'
GROUP BY date, guardduty_type, guardduty_severity
ORDER BY findings DESC;
EOF
}

resource "aws_athena_named_query" "identity_ot_source_overlap" {
  count     = var.enable_analytics ? 1 : 0
  name      = "identity_ot_source_overlap"
  workgroup = aws_athena_workgroup.ot_analytics[0].id
  database  = aws_glue_catalog_database.ot_telemetry[0].name
  query     = <<EOF
SELECT
  c.date,
  c.user_name,
  c.source_ip,
  o.alert_reason,
  count(*) AS events
FROM staged_telemetry c
JOIN staged_telemetry o
  ON c.source_ip = o.src_ip
WHERE c.source = 'cloudtrail'
  AND o.source IN ('ot_sensor', 'iptables')
GROUP BY c.date, c.user_name, c.source_ip, o.alert_reason
ORDER BY events DESC;
EOF
}

resource "aws_athena_named_query" "k8s_exec_events" {
  count     = var.enable_analytics ? 1 : 0
  name      = "k8s_exec_events"
  workgroup = aws_athena_workgroup.ot_analytics[0].id
  database  = aws_glue_catalog_database.ot_telemetry[0].name
  query     = <<EOF
SELECT
  date,
  username,
  namespace,
  object_name,
  verb,
  subresource,
  response_code,
  source_ip
FROM staged_telemetry
WHERE source = 'k8s_audit'
  AND resource = 'pods'
  AND subresource IN ('exec', 'attach')
ORDER BY timestamp DESC;
EOF
}

resource "aws_athena_named_query" "k8s_privileged_workloads" {
  count     = var.enable_analytics ? 1 : 0
  name      = "k8s_privileged_workloads"
  workgroup = aws_athena_workgroup.ot_analytics[0].id
  database  = aws_glue_catalog_database.ot_telemetry[0].name
  query     = <<EOF
SELECT
  date,
  username,
  namespace,
  object_name,
  resource,
  container_image,
  request_object
FROM staged_telemetry
WHERE source = 'k8s_audit'
  AND (
    request_object LIKE '%"privileged": true%'
    OR request_object LIKE '%hostPath%'
  )
ORDER BY date DESC;
EOF
}

resource "aws_athena_named_query" "k8s_rbac_changes" {
  count     = var.enable_analytics ? 1 : 0
  name      = "k8s_rbac_changes"
  workgroup = aws_athena_workgroup.ot_analytics[0].id
  database  = aws_glue_catalog_database.ot_telemetry[0].name
  query     = <<EOF
SELECT
  date,
  verb,
  username,
  resource,
  namespace,
  object_name,
  source_ip,
  response_code
FROM staged_telemetry
WHERE source = 'k8s_audit'
  AND resource IN ('roles', 'clusterroles', 'rolebindings', 'clusterrolebindings')
ORDER BY timestamp DESC;
EOF
}

resource "aws_athena_named_query" "k8s_anonymous_access" {
  count     = var.enable_analytics ? 1 : 0
  name      = "k8s_anonymous_access"
  workgroup = aws_athena_workgroup.ot_analytics[0].id
  database  = aws_glue_catalog_database.ot_telemetry[0].name
  query     = <<EOF
SELECT
  date,
  verb,
  resource,
  namespace,
  object_name,
  source_ip,
  response_code
FROM staged_telemetry
WHERE source = 'k8s_audit'
  AND (
    username = 'system:anonymous'
    OR user_groups LIKE '%system:unauthenticated%'
  )
ORDER BY timestamp DESC;
EOF
}

resource "aws_athena_named_query" "falco_high_severity" {
  count     = var.enable_analytics ? 1 : 0
  name      = "falco_high_severity"
  workgroup = aws_athena_workgroup.ot_analytics[0].id
  database  = aws_glue_catalog_database.ot_telemetry[0].name
  query     = <<EOF
SELECT
  date,
  falco_rule,
  falco_priority,
  namespace,
  pod,
  process,
  command,
  source_ip
FROM staged_telemetry
WHERE source = 'falco'
  AND severity IN ('HIGH', 'MEDIUM')
ORDER BY timestamp DESC;
EOF
}

resource "aws_athena_named_query" "vuln_open_by_priority" {
  count     = var.enable_analytics ? 1 : 0
  name      = "vuln_open_by_priority"
  workgroup = aws_athena_workgroup.ot_analytics[0].id
  database  = aws_glue_catalog_database.ot_telemetry[0].name
  query     = <<EOF
SELECT
  priority_bucket,
  count(*) AS findings,
  count(DISTINCT asset_id) AS assets,
  round(avg(priority_score), 1) AS avg_score
FROM vulnerability_findings
WHERE status = 'open'
GROUP BY priority_bucket
ORDER BY avg_score DESC;
EOF
}

resource "aws_athena_named_query" "vuln_top_remediation" {
  count     = var.enable_analytics ? 1 : 0
  name      = "vuln_top_remediation"
  workgroup = aws_athena_workgroup.ot_analytics[0].id
  database  = aws_glue_catalog_database.ot_telemetry[0].name
  query     = <<EOF
SELECT
  finding_id,
  priority_bucket,
  priority_score,
  asset_id,
  hostname,
  title,
  cve_ids,
  cvss_score,
  epss_score,
  kev,
  due_date
FROM vulnerability_findings
WHERE status = 'open'
ORDER BY priority_score DESC
LIMIT 50;
EOF
}

resource "aws_athena_named_query" "vuln_kev_exposure" {
  count     = var.enable_analytics ? 1 : 0
  name      = "vuln_kev_exposure"
  workgroup = aws_athena_workgroup.ot_analytics[0].id
  database  = aws_glue_catalog_database.ot_telemetry[0].name
  query     = <<EOF
SELECT
  asset_id,
  hostname,
  title,
  cve_ids,
  kev_date,
  priority_score,
  due_date
FROM vulnerability_findings
WHERE status = 'open'
  AND kev = true
ORDER BY priority_score DESC;
EOF
}

resource "aws_athena_named_query" "vuln_sla_breaches" {
  count     = var.enable_analytics ? 1 : 0
  name      = "vuln_sla_breaches"
  workgroup = aws_athena_workgroup.ot_analytics[0].id
  database  = aws_glue_catalog_database.ot_telemetry[0].name
  query     = <<EOF
SELECT
  priority_bucket,
  count(*) AS breaches,
  min(due_date) AS oldest_due,
  max(priority_score) AS max_score
FROM vulnerability_findings
WHERE status = 'open'
  AND due_date < CAST(current_date AS varchar)
GROUP BY priority_bucket
ORDER BY max_score DESC;
EOF
}

resource "aws_athena_named_query" "vuln_asset_risk" {
  count     = var.enable_analytics ? 1 : 0
  name      = "vuln_asset_risk"
  workgroup = aws_athena_workgroup.ot_analytics[0].id
  database  = aws_glue_catalog_database.ot_telemetry[0].name
  query     = <<EOF
SELECT
  asset_id,
  max(hostname) AS hostname,
  max(asset_criticality) AS criticality,
  count(*) AS findings,
  sum(CASE WHEN priority_bucket = 'CRITICAL' THEN 1 ELSE 0 END) AS critical_findings,
  max(priority_score) AS max_score
FROM vulnerability_findings
WHERE status = 'open'
GROUP BY asset_id
ORDER BY criticality DESC, max_score DESC;
EOF
}

resource "aws_athena_named_query" "vuln_cve_prevalence" {
  count     = var.enable_analytics ? 1 : 0
  name      = "vuln_cve_prevalence"
  workgroup = aws_athena_workgroup.ot_analytics[0].id
  database  = aws_glue_catalog_database.ot_telemetry[0].name
  query     = <<EOF
SELECT
  cve_id,
  count(DISTINCT asset_id) AS assets,
  count(*) AS findings,
  max(priority_score) AS max_score,
  max(CASE WHEN kev THEN 1 ELSE 0 END) AS kev
FROM vulnerability_findings
CROSS JOIN UNNEST(split(cve_ids, ',')) AS t(cve_id)
WHERE status = 'open'
  AND cve_ids <> ''
GROUP BY cve_id
ORDER BY assets DESC, max_score DESC
LIMIT 50;
EOF
}
