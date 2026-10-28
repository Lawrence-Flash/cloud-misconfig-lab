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

# PLANTED: SSH from the whole IPv4 internet.
resource "aws_security_group_rule" "app_ssh" {
  type              = "ingress"
  description       = "SSH from anywhere"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.app.id
}

# PLANTED: RDP from the whole IPv4 internet.
resource "aws_security_group_rule" "app_rdp" {
  type              = "ingress"
  description       = "RDP from anywhere"
  from_port         = 3389
  to_port           = 3389
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.app.id
}

resource "aws_security_group_rule" "app_egress_all" {
  type              = "egress"
  description       = "All egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.app.id
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

  # PLANTED: optional tokens means IMDSv1 is still accepted.
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "optional"
    http_put_response_hop_limit = 1
  }

  # PLANTED: root volume is not encrypted.
  root_block_device {
    volume_type = "gp3"
    volume_size = 20
    encrypted   = false
  }

  tags = merge(local.common_tags, {
    Name = "lab-app"
  })
}

# PLANTED: data volume is not encrypted.
resource "aws_ebs_volume" "data" {
  availability_zone = aws_subnet.private_a.availability_zone
  size              = 20
  type              = "gp3"
  encrypted         = false

  tags = merge(local.common_tags, {
    Name = "lab-data"
  })
}

resource "aws_volume_attachment" "data" {
  device_name = "/dev/sdf"
  volume_id   = aws_ebs_volume.data.id
  instance_id = aws_instance.app.id
}
