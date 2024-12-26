# Input Variables
variable "access_key" {
  description = "AWS access key"
  type        = string
}

variable "secret_key" {
  description = "AWS secret key"
  type        = string
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
    private_key = file("~/.ssh/test.pem")
    host        = self.public_ip
  }

  provisioner "file" {
    source      = "./pown.sh"
    destination = "/home/admin/pown.sh"
  }

  provisioner "remote-exec" {
    inline = [
      "sudo apt update -y",
      "sudo bash /home/admin/pown.sh"
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
    private_key = file("~/.ssh/test.pem")
    host        = self.public_ip
  }

  provisioner "file" {
    source      = "./pown.sh"
    destination = "/home/ec2-user/pown.sh"
  }

  provisioner "file" {
    source      = "./.env"
    destination = "/home/ec2-user/.env"
  }

  provisioner "remote-exec" {
    inline = [
      "sudo yum update -y",
      "chmod +x /home/ec2-user/pown.sh",
      "chmod 600 /home/ec2-user/.env",
      "sudo mv /home/ec2-user/.env /home/ec2-user/pown.sh /root/",
      "cd /root && sudo bash pown.sh"
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