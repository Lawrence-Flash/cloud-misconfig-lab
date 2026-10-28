resource "aws_vpc" "lab" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = merge(local.common_tags, {
    Name = "lab-vpc"
  })
}

resource "aws_subnet" "private_a" {
  vpc_id                  = aws_vpc.lab.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = false

  tags = merge(local.common_tags, {
    Name = "lab-private-a"
  })
}

resource "aws_subnet" "private_b" {
  vpc_id                  = aws_vpc.lab.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = "${var.aws_region}b"
  map_public_ip_on_launch = false

  tags = merge(local.common_tags, {
    Name = "lab-private-b"
  })
}

# Empty on purpose: the default security group should not allow traffic.
resource "aws_default_security_group" "lab" {
  vpc_id = aws_vpc.lab.id

  tags = merge(local.common_tags, {
    Name = "lab-default-locked"
  })
}

resource "aws_flow_log" "lab" {
  vpc_id               = aws_vpc.lab.id
  traffic_type         = "ALL"
  log_destination_type = "s3"
  log_destination      = aws_s3_bucket.logs.arn

  tags = merge(local.common_tags, {
    Name = "lab-vpc-flow"
  })
}
