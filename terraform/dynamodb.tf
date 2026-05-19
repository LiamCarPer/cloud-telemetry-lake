resource "aws_dynamodb_table" "ot_detections" {
  name         = "ot_detections"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "incident_correlator"
  range_key    = "timestamp"

  attribute {
    name = "incident_correlator"
    type = "S"
  }

  attribute {
    name = "timestamp"
    type = "S"
  }

  attribute {
    name = "severity"
    type = "S"
  }

  attribute {
    name = "host"
    type = "S"
  }

  global_secondary_index {
    name            = "severity-index"
    hash_key        = "severity"
    range_key       = "timestamp"
    projection_type = "ALL"
  }

  global_secondary_index {
    name            = "host-index"
    hash_key        = "host"
    range_key       = "timestamp"
    projection_type = "ALL"
  }

  tags = {
    Environment = var.environment
    Project     = "ot-telemetry"
  }
}

resource "aws_dynamodb_table" "ot_detection_state" {
  name         = "ot_detection_state"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "state_key"

  attribute {
    name = "state_key"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  tags = {
    Environment = var.environment
    Project     = "ot-telemetry"
  }
}
