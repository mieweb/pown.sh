# Provider configuration for AWS
provider "aws" {
  region     = "us-east-1"
  access_key = var.access_key
  secret_key = var.secret_key
}

# Security group allowing SSH access on port 22
resource "aws_security_group" "allow_ssh" {
  name_prefix = "allow_ssh"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Allow SSH from any IP address (for testing)
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]  # Allow outbound traffic
  }
}

# EC2 instance resource configuration
resource "aws_instance" "amazon_linux" {
  ami           = "ami-01816d07b1128cd2d"  # Replace with the correct Amazon Linux AMI ID for your region
  instance_type = "t2.micro"               # Instance type
  security_groups = [aws_security_group.allow_ssh.name]
  key_name       = "test"

  # SSH connection configuration
  connection {
    type        = "ssh"
    user        = "ec2-user"            # Default user for Amazon Linux
    private_key = file("~/.ssh/test.pem")    # Your private key for SSH access
    host        = self.public_ip          # Public IP of the instance
  }

  # Provisioner to upload pown.sh and run it after instance creation
  provisioner "file" {
    source      = "./pown.sh"                  # Path to the pown.sh file on your local machine
    destination = "/home/ec2-user/pown.sh"     # Destination path on the EC2 instance
  }

  # Provisioner to run the pown.sh script after instance creation
  provisioner "remote-exec" {
    inline = [
      "sudo yum update -y",                # Update the system
      "sudo bash /home/ec2-user/pown.sh"  # Run the pown.sh script
    ]
  }

  tags = {
    Name = "AmazonLinuxInstance"
  }
}

# Output the public IP of the instance
output "instance_public_ip" {
  value = aws_instance.amazon_linux.public_ip
}

