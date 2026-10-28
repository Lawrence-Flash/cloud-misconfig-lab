resource "aws_db_subnet_group" "lab" {
  name       = "lab-db-subnets"
  subnet_ids = [aws_subnet.private_a.id, aws_subnet.private_b.id]

  tags = merge(local.common_tags, {
    Name = "lab-db-subnets"
  })
}

resource "aws_db_instance" "lab" {
  identifier     = "lab-mysql"
  engine         = "mysql"
  engine_version = "8.0"
  instance_class = "db.t3.micro"

  allocated_storage     = 20
  max_allocated_storage = 100
  storage_type          = "gp3"
  db_name               = "labdb"
  username              = "labapp"

  # FIXED: no password in source. AWS stores the master password in Secrets Manager.
  manage_master_user_password = true

  db_subnet_group_name   = aws_db_subnet_group.lab.name
  vpc_security_group_ids = [aws_security_group.db.id]

  publicly_accessible                 = false
  storage_encrypted                   = true
  kms_key_id                          = aws_kms_key.lab.arn
  backup_retention_period             = 7
  backup_window                       = "02:00-03:00"
  maintenance_window                  = "sun:03:00-sun:04:00"
  copy_tags_to_snapshot               = true
  skip_final_snapshot                 = false
  final_snapshot_identifier           = "lab-mysql-final"
  deletion_protection                 = true
  multi_az                            = true
  auto_minor_version_upgrade          = true
  iam_database_authentication_enabled = true
  enabled_cloudwatch_logs_exports     = ["error", "general", "slowquery"]
  performance_insights_enabled        = true
  performance_insights_kms_key_id     = aws_kms_key.lab.arn
  monitoring_interval                 = 60
  monitoring_role_arn                 = aws_iam_role.rds_monitoring.arn

  tags = merge(local.common_tags, {
    Name = "lab-mysql"
  })
}
