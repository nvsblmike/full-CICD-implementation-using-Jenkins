# main.tf
terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = {
      Environment   = "Production"
      Terraform     = "true"
      Project       = "CI/CD Pipeline"
      CostCenter    = "DevOps"
    }
  }
}

module "vpc" {
  source = "terraform-aws-modules/vpc/aws"
  version = "5.0.0"
  
  name   = "main-vpc"
  cidr   = "10.0.0.0/16"

  azs             = ["${var.aws_region}a"]
  public_subnets  = ["10.0.1.0/24"]
  private_subnets = ["10.0.2.0/24"]

  enable_nat_gateway     = true
  single_nat_gateway     = true

  enable_dns_support = true
  enable_dns_hostnames = true

  public_subnet_tags = {
    "NetworkTier" = "Public"
  }

  private_subnet_tags = {
    "NetworkTier" = "Private"
  }
}

# SSH Key Management
resource "tls_private_key" "ssh_key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "generated_key" {
  key_name   = "secret-key-${var.environment}"
  public_key = tls_private_key.ssh_key.public_key_openssh
}

resource "local_file" "private_key" {
  content  = tls_private_key.ssh_key.private_key_pem
  filename = "${path.module}/.ssh/secret-private-key.pem"
  file_permission = "0600"
}

# resource "aws_eip" "nat" {}

# resource "aws_nat_gateway" "nat" {
#   allocation_id = aws_eip.nat.id
#   subnet_id     = module.vpc.public_subnets[0]
# }

resource "aws_security_group" "jenkins_sg" {
  name        = "jenkins-sg"
  description = "Jenkins security group"
  vpc_id = module.vpc.vpc_id

  ingress {
    description     = "SSH from Ansible Controller"
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.ansible_sg.id]
  }
  
  ingress {
    description = "Jenkins Web Interface"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Role = "Jenkins"
  }
}

resource "aws_security_group" "sonarqube_sg" {
  name        = "sonarqube-sg"
  description = "Sonarqube security group"
  vpc_id = module.vpc.vpc_id
  
  ingress {
    from_port   = 9000
    to_port     = 9000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    # security_groups = [aws_security_group.ansible_sg.id]
  }

  ingress {
    description     = "SSH from Ansible Controller"
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.ansible_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Role = "SonarQube"
  }
}

resource "aws_security_group" "k8s_master_sg" {
  name        = "K8s-master-sg"
  description = "Kubernetes Master security group"
  vpc_id = module.vpc.vpc_id
  
  ingress {
    from_port   = 6443
    to_port     = 6443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description     = "SSH from Ansible Controller"
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.ansible_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Role = "Kubernetes-Master"
  }
}

resource "aws_security_group" "k8s_worker_sg" {
  name        = "K8s-worker-sg"
  description = "Kubernetes Worker security group"
  vpc_id = module.vpc.vpc_id
  
  ingress {
    from_port   = 32630
    to_port     = 32630
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description     = "SSH from Ansible Controller"
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.ansible_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Role = "Kubernetes-Worker"
  }
}

resource "aws_security_group" "prometheus_sg" {
  name        = "prometheus-grafana-sg"
  description = "Prometheus and Grafana security group"
  vpc_id = module.vpc.vpc_id
  
  ingress {
    from_port   = 9090
    to_port     = 9090
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description     = "SSH from Ansible Controller"
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.ansible_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Role = "Prometheus-grafana"
  }
}

resource "aws_security_group" "nexus_sg" {
  name        = "nexus-sg"
  description = "Nexus security group"
  vpc_id = module.vpc.vpc_id
  
  ingress {
    from_port   = 8081
    to_port     = 8081
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description     = "SSH from Ansible Controller"
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.ansible_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Role = "Nexus"
  }
}

resource "aws_security_group" "ansible_sg" {
  name        = "ansible-sg"
  description = "Ansible security group"
  vpc_id = module.vpc.vpc_id
  
  ingress {
    description = "SSH from trusted IPs"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Role = "Ansible"
  }
}

resource "aws_instance" "jenkins" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = "t3.medium"
  subnet_id              = module.vpc.public_subnets[0]
  vpc_security_group_ids = [aws_security_group.jenkins_sg.id]
  key_name               = aws_key_pair.generated_key.key_name

  monitoring             = true
  associate_public_ip_address = true

  root_block_device {
    volume_size = 30
    volume_type = "gp3"
  }

  tags = {
    Name = "Jenkins"
  }
}

resource "aws_instance" "sonarqube" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = "t2.micro"
  subnet_id              = module.vpc.public_subnets[0]
  vpc_security_group_ids = [aws_security_group.sonarqube_sg.id]
  key_name               = aws_key_pair.generated_key.key_name

  monitoring             = true
  associate_public_ip_address = true

  root_block_device {
    volume_size = 30
    volume_type = "gp3"
  }

  tags = {
    Name = "Sonarqube"
  }
}

resource "aws_instance" "k8s_master" {
  ami                    = data.aws_ami.ubuntu.id 
  instance_type          = "t3.micro"
  subnet_id              = module.vpc.public_subnets[0]
  vpc_security_group_ids = [aws_security_group.k8s_master_sg.id]
  key_name               = aws_key_pair.generated_key.key_name

  monitoring             = true
  associate_public_ip_address = true

  root_block_device {
    volume_size = 30
    volume_type = "gp3"
  }

  tags = {
    Name = "Kubernetes_master"
  }
}

resource "aws_instance" "k8s_worker" {
  count = 2
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = "t2.micro"
  subnet_id              = module.vpc.public_subnets[0]
  vpc_security_group_ids = [aws_security_group.k8s_worker_sg.id]
  key_name               = aws_key_pair.generated_key.key_name

  monitoring             = true
  associate_public_ip_address = true

  root_block_device {
    volume_size = 30
    volume_type = "gp3"
  }

  tags = {
    Name = "K8s-worker"
  }

  lifecycle {
    ignore_changes = [ami]
  }
}

resource "aws_instance" "prometheus" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = "t2.micro"
  subnet_id              = module.vpc.public_subnets[0]
  vpc_security_group_ids = [aws_security_group.prometheus_sg.id]
  key_name               = aws_key_pair.generated_key.key_name

  monitoring             = true
  associate_public_ip_address = true

  root_block_device {
    volume_size = 30
    volume_type = "gp3"
  }

  tags = {
    Name = "Prometheus-grafana"
  }
}

resource "aws_instance" "nexus" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = "t3.micro"
  subnet_id              = module.vpc.public_subnets[0]
  vpc_security_group_ids = [aws_security_group.nexus_sg.id]
  key_name               = aws_key_pair.generated_key.key_name

  monitoring             = true
  associate_public_ip_address = true

  root_block_device {
    volume_size = 30
    volume_type = "gp3"
  }

  tags = {
    Name = "nexus"
  }
}

resource "aws_instance" "ansible_controller" {
  ami                    = data.aws_ami.ubuntu.id 
  instance_type          = "t2.micro"
  subnet_id              = module.vpc.public_subnets[0]
  vpc_security_group_ids = [aws_security_group.ansible_sg.id]
  key_name               = aws_key_pair.generated_key.key_name

  monitoring             = true
  associate_public_ip_address = true

  user_data = templatefile("${path.module}/ansible-controller-setup.sh.tpl", {
    private_key_content = tls_private_key.ssh_key.private_key_pem
    ansible_user        = "ubuntu"
    SSH_DIR             = "/home/ubuntu/.ssh"
  })

  root_block_device {
    volume_size = 30
    volume_type = "gp3"
  }

  tags = {
    Name = "Ansible-Controller"
  }
}

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["amazon"] # Canonical's AWS account ID

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# resource "aws_instance" "servers" {
#   for_each      = {
#     jenkins      = { type = "t3.medium", sg = aws_security_group.jenkins_sg.id }
#     sonarqube    = { type = "t3.medium", sg = aws_security_group.sonarqube_sg.id }
#     k8s_master   = { type = "t3.medium", sg = aws_security_group.k8s_master_sg.id }
#     k8s_worker_1 = { type = "t3.medium", sg = aws_security_group.k8s_worker_sg.id }
#     k8s_worker_2 = { type = "t3.medium", sg = aws_security_group.k8s_worker_sg.id }
#     prometheus   = { type = "t3.medium", sg = aws_security_group.prometheus_sg.id }
#     nexus        = { type = "t3.medium", sg = aws_security_group.nexus_sg.id }

#   }
#   ami           = "ami-0c55b159cbfafe1f0" # Ubuntu 20.04
#   instance_type = each.value.type
#   subnet_id     = module.vpc.public_subnets[0]
#   security_groups = [each.value.sg]
#   key_name               = aws_key_pair.generated_key.key_name

#   monitoring             = true
#   associate_public_ip_address = true
  
#   root_block_device {
#     volume_size = 30
#     volume_type = "gp3"
#   }

#   tags = {
#     Name = each.key
#   }
# }

# resource "aws_iam_role" "ansible_role" {
#   name = "ansible-server-role"
#   assume_role_policy = <<EOF
# {
#   "Version": "2012-10-17",
#   "Statement": [
#     {
#       "Action": "sts:AssumeRole",
#       "Principal": {
#         "Service": "ec2.amazonaws.com"
#       },
#       "Effect": "Allow"
#     }
#   ]
# }
# EOF
# }

# resource "aws_iam_instance_profile" "ansible_profile" {
#   name = "ansible-profile"
#   role = aws_iam_role.ansible_role.name
# }
