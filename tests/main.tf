terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
  required_version = ">= 1.3.0"
}

# Input Variables
variable "access_key" {
  description = "AWS access key"
  type        = string
}

variable "secret_key" {
  description = "AWS secret key"
  type        = string
}

variable "private_key" {
  description = "SSH private key"
  type        = string
  sensitive   = true
}

# Provider Configuration
provider "aws" {
  region     = "us-east-1"
  access_key = var.access_key
  secret_key = var.secret_key
}

# Common Security Group
resource "aws_security_group" "allow_ssh" {
  name_prefix = "allow_ssh"

  ingress {
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
}

# Debian Instance
resource "aws_instance" "debian" {
  ami             = "ami-064519b8c76274859"
  instance_type   = "t2.micro"
  security_groups = [aws_security_group.allow_ssh.name]
  key_name        = "test"

  connection {
    type        = "ssh"
    user        = "admin"
    private_key = var.private_key
    host        = self.public_ip
  }

  provisioner "file" {
    source      = "../pown.sh"
    destination = "/home/admin/pown.sh"
  }

  provisioner "file" {
    source      = "./.env"
    destination = "/home/admin/.env"
    on_failure  = "continue"  # Add this to see if file transfer fails
  }

  provisioner "remote-exec" {
    inline = [
      "pwd",
      "echo 'Step 1: Checking original .env'",
      "ls -la /home/admin/.env",
      "echo 'Step 2: Setting permissions'",
      "sudo chmod 600 /home/admin/.env",
      "echo 'Step 3: Copying to root'",
      "sudo cp /home/admin/.env /root/.env",
      "echo 'Step 4: Verifying root .env'",
      "sudo ls -la /root/.env",
      "echo 'Step 5: Checking if file exists'",
      "sudo test -f /root/.env && echo 'File exists' || echo 'File does not exist'",
      "echo 'Step 6: Checking file contents'",
      "sudo cat /root/.env | wc -l",
      "if sudo test -s /root/.env; then",
      "  echo '.env file exists and has content'",
      "  sudo cp /home/admin/pown.sh /root/pown.sh || echo 'Failed to copy pown.sh'",
      "  sudo chmod +x /root/pown.sh || echo 'Failed to make pown.sh executable'",
      "  sudo bash /home/admin/pown.sh",
      "else",
      "  echo '.env file is empty or missing'",
      "  exit 1",
      "fi"
    ]
  }

  tags = {
    Name = "DebianInstance"
  }
}

# Amazon Linux Instance
resource "aws_instance" "amazon_linux" {
  ami             = "ami-01816d07b1128cd2d"
  instance_type   = "t2.micro"
  security_groups = [aws_security_group.allow_ssh.name]
  key_name        = "test"

  connection {
    type        = "ssh"
    user        = "ec2-user"
    private_key = var.private_key
    host        = self.public_ip
  }

  provisioner "file" {
    source      = "../pown.sh"
    destination = "/home/ec2-user/pown.sh"
  }

  provisioner "file" {
    source      = "./.env"
    destination = "/home/ec2-user/.env"
  }

  provisioner "remote-exec" {
    inline = [
      "pwd",
      "echo 'Step 1: Checking original .env'",
      "ls -la /home/ec2-user/.env",
      "echo 'Step 2: Setting permissions'",
      "sudo chmod 600 /home/ec2-user/.env",
      "echo 'Step 3: Copying to root'",
      "sudo cp /home/ec2-user/.env /root/.env",
      "echo 'Step 4: Verifying root .env'",
      "sudo ls -la /root/.env",
      "echo 'Step 5: Checking if file exists'",
      "sudo test -f /root/.env && echo 'File exists' || echo 'File does not exist'",
      "echo 'Step 6: Checking file contents'",
      "sudo cat /root/.env | wc -l",
      "if sudo test -s /root/.env; then",
      "  echo '.env file exists and has content'",
      "  sudo bash /home/ec2-user/pown.sh",
      "else",
      "  echo '.env file is empty or missing'",
      "  exit 1",
      "fi"
    ]
  }

  tags = {
    Name = "AmazonLinuxInstance"
  }
}

# Outputs
output "debian_public_ip" {
  value = aws_instance.debian.public_ip
}

output "amazon_linux_public_ip" {
  value = aws_instance.amazon_linux.public_ip
}
