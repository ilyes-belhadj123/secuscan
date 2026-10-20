# Benchmark : même infrastructure, configurée de façon sûre (aucune alerte attendue).
resource "aws_s3_bucket_public_access_block" "exports" {
  bucket                  = aws_s3_bucket.exports.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_security_group" "admin" {
  name = "admin"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.office_cidr]
  }
}

resource "aws_db_instance" "orders" {
  engine                      = "postgres"
  instance_class              = "db.t3.micro"
  username                    = "acme"
  manage_master_user_password = true
  publicly_accessible         = false
  storage_encrypted           = true
}

resource "aws_iam_policy" "deploy" {
  name = "deploy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["ecs:UpdateService", "ecs:DescribeServices"]
      Resource = aws_ecs_service.api.id
    }]
  })
}
