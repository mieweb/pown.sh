variable "access_key" {
  description = "AWS access key"
  type        = string
}

variable "secret_key" {
  description = "AWS secret key"
  type        = string
}

provider "aws" {
  region     = "us-east-1"
  access_key = var.access_key
  secret_key = var.secret_key
}

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

resource "aws_instance" "debian" {
  ami             = "ami-064519b8c76274859"
  instance_type   = "t2.micro"
  security_groups = [aws_security_group.allow_ssh.name]
  key_name        = "test"

  user_data = <<-EOF
              #!/bin/bash
              echo 'Step 1: Creating .env file'
              cat << 'ENVFILE' > /root/.env
              $(cat .env)
              ENVFILE
              
              chmod 600 /root/.env
              
              echo 'Step 2: Creating pown script'
              cat << 'SCRIPT' > /root/pown.sh
              $(cat ../pown.sh)
              SCRIPT
              
              chmod +x /root/pown.sh
              bash /root/pown.sh
              EOF

  tags = {
    Name = "DebianInstance"
  }
}

resource "aws_instance" "amazon_linux" {
  ami             = "ami-01816d07b1128cd2d"
  instance_type   = "t2.micro"
  security_groups = [aws_security_group.allow_ssh.name]
  key_name        = "test"

  user_data = <<-EOF
              #!/bin/bash
              echo 'Step 1: Creating .env file'
              cat << 'ENVFILE' > /root/.env
              $(cat .env)
              ENVFILE
              
              chmod 600 /root/.env
              
              echo 'Step 2: Creating pown script'
              cat << 'SCRIPT' > /root/pown.sh
              $(cat ../pown.sh)
              SCRIPT
              
              chmod +x /root/pown.sh
              bash /root/pown.sh
              EOF

  tags = {
    Name = "AmazonLinuxInstance"
  }
}

output "debian_public_ip" {
  value = aws_instance.debian.public_ip
}

output "amazon_linux_public_ip" {
  value = aws_instance.amazon_linux.public_ip
}