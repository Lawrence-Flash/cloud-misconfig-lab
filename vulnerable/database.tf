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

  allocated_storage = 20
  storage_type      = "gp3"
  db_name           = "labdb"
  username          = "labapp"
  password          = var.db_password

  db_subnet_group_name   = aws_db_subnet_group.lab.name
  vpc_security_group_ids = [aws_security_group.db.id]

  # PLANTED: the instance is reachable from outside the VPC, the disk is not
  # encrypted, and automated backups are off.
  publicly_accessible     = true
  storage_encrypted       = false
  backup_retention_period = 0
  skip_final_snapshot     = true
  deletion_protection     = false
  multi_az                = false

  tags = merge(local.common_tags, {
    Name = "lab-mysql"
  })
}
