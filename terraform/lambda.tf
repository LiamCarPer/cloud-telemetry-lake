data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../src/parser_lambda"
  output_path = "${path.module}/../parser_lambda.zip"
  # NOTE: LocalStack Community Edition workaround.
  # Because LocalStack Community does not support standard runtime mounting of Lambda layers to /opt,
  # we bundle all dependencies (pandas, awswrangler, etc.) directly into the fat zip.
  # Uncomment the excludes below when deploying to real AWS using standard layers.
  # excludes    = [
  #   "python",
  #   "python/**"
  # ]
}

resource "aws_s3_object" "lambda_zip_upload" {
  bucket = aws_s3_bucket.telemetry_buckets["raw"].id
  key    = "parser_lambda.zip"
  source = data.archive_file.lambda_zip.output_path
  etag   = filemd5(data.archive_file.lambda_zip.output_path)
}

resource "aws_lambda_layer_version" "pandas_layer" {
  filename            = "${path.module}/../pandas_layer.zip"
  layer_name          = "pandas_awswrangler_layer"
  compatible_runtimes = ["python3.12"]
}

resource "aws_lambda_function" "parser_lambda" {
  s3_bucket        = aws_s3_bucket.telemetry_buckets["raw"].id
  s3_key           = aws_s3_object.lambda_zip_upload.key
  function_name    = "ot-log-parser-lambda"
  role             = aws_iam_role.lambda_exec.arn
  handler          = "handler.lambda_handler"
  runtime          = "python3.12"
  timeout          = 180
  memory_size      = 512
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  # NOTE: LocalStack Community Edition workaround.
  # If deploying to real AWS, uncomment the layers block below and exclude dependencies from the zip.
  # layers = [
  #   aws_lambda_layer_version.pandas_layer.arn
  # ]

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
