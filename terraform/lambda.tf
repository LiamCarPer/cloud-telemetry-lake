data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../src/parser_lambda"
  output_path = "${path.module}/../parser_lambda.zip"
  excludes    = [
    "python",
    "python/**"
  ]
}

resource "aws_lambda_layer_version" "pandas_layer" {
  filename            = "${path.module}/../pandas_layer.zip"
  layer_name          = "pandas_awswrangler_layer"
  compatible_runtimes = ["python3.12"]
}

resource "aws_lambda_function" "parser_lambda" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "ot-log-parser-lambda"
  role             = aws_iam_role.lambda_exec.arn
  handler          = "handler.lambda_handler"
  runtime          = "python3.12"
  timeout          = 180
  memory_size      = 512
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  layers = [
    aws_lambda_layer_version.pandas_layer.arn
  ]

  environment {
    variables = {
      RAW_BUCKET       = aws_s3_bucket.telemetry_buckets["raw"].id
      STAGED_BUCKET    = aws_s3_bucket.telemetry_buckets["staged"].id
      DLQ_BUCKET       = aws_s3_bucket.telemetry_buckets["dlq"].id
      AWS_ENDPOINT_URL = "http://localhost:4566"
    }
  }
}

resource "aws_lambda_event_source_mapping" "sqs_trigger" {
  event_source_arn = aws_sqs_queue.ingest_queue.arn
  function_name    = aws_lambda_function.parser_lambda.arn
  batch_size       = 5
  enabled          = true
}
