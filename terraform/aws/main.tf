# Simple deployment using AWS ECS Fargate

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
  required_version = ">= 1.0"
}

provider "aws" {
  region = var.aws_region
}

resource "aws_ecs_cluster" "this" {
  name = "auth-translator"
}

resource "aws_ecs_task_definition" "this" {
  family                   = "auth-translator"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = var.execution_role_arn

  container_definitions = jsonencode([
    {
      name  = "auth-translator"
      image = var.container_image
      portMappings = [{
        containerPort = 8080
        hostPort      = 8080
        protocol      = "tcp"
      }]
      command = concat([
        "./authtranslator"
        ], var.redis_address != "" ? ["-redis-addr", var.redis_address] : [],
        var.redis_ca != "" ? ["-redis-ca", var.redis_ca] : [])
    }
  ])
}

resource "aws_ecs_service" "this" {
  name            = "auth-translator"
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.this.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets         = var.subnet_ids
    security_groups = [var.security_group_id]
  }
}

output "service_name" {
  value = aws_ecs_service.this.name
}
