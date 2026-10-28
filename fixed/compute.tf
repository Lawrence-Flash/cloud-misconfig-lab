resource "aws_security_group" "app" {
  name        = "lab-app"
  description = "Application instances"
  vpc_id      = aws_vpc.lab.id

  tags = merge(local.common_tags, {
    Name = "lab-app"
  })
}

resource "aws_security_group" "db" {
  name        = "lab-db"
  description = "Database instances"
  vpc_id      = aws_vpc.lab.id

  tags = merge(local.common_tags, {
    Name = "lab-db"
  })
}

# FIXED: SSH only from the lab VPC. RDP is not open.
resource "aws_security_group_rule" "app_ssh" {
  type              = "ingress"
  description       = "SSH from inside the lab VPC"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["10.0.0.0/16"]
  security_group_id = aws_security_group.app.id
}

resource "aws_security_group_rule" "app_egress_mysql" {
  type                     = "egress"
  description              = "MySQL to the database security group"
  from_port                = 3306
  to_port                  = 3306
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.db.id
  security_group_id        = aws_security_group.app.id
}

resource "aws_security_group_rule" "db_mysql" {
  type                     = "ingress"
  description              = "MySQL from the application security group"
  from_port                = 3306
  to_port                  = 3306
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.app.id
  security_group_id        = aws_security_group.db.id
}

resource "aws_instance" "app" {
  ami                         = var.ami_id
  instance_type               = "t3.medium"
  ebs_optimized               = true
  subnet_id                   = aws_subnet.private_a.id
  vpc_security_group_ids      = [aws_security_group.app.id]
  iam_instance_profile        = aws_iam_instance_profile.app.name
  associate_public_ip_address = false
  monitoring                  = true

  # FIXED: IMDSv2 only. Requests without a session token are refused.
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_type = "gp3"
    volume_size = 20
    encrypted   = true
    kms_key_id  = aws_kms_key.lab.arn
  }

  tags = merge(local.common_tags, {
    Name = "lab-app"
  })
}

resource "aws_ebs_volume" "data" {
  availability_zone = aws_subnet.private_a.availability_zone
  size              = 20
  type              = "gp3"
  encrypted         = true
  kms_key_id        = aws_kms_key.lab.arn

  tags = merge(local.common_tags, {
    Name = "lab-data"
  })
}

resource "aws_volume_attachment" "data" {
  device_name = "/dev/sdf"
  volume_id   = aws_ebs_volume.data.id
  instance_id = aws_instance.app.id
}
