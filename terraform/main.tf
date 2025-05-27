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
  name = "auth-transformer"
}

resource "aws_ecs_task_definition" "this" {
  family                   = "auth-transformer"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = var.execution_role_arn

  container_definitions = jsonencode([
    {
      name  = "auth-transformer"
      image = var.container_image
      portMappings = [{
        containerPort = 8080
        hostPort      = 8080
        protocol      = "tcp"
      }]
      environment = [
        {
          name  = "IN_TOKEN"
          value = var.in_token
        },
        {
          name  = "OUT_TOKEN"
          value = var.out_token
        }
      ]
    }
  ])
}

resource "aws_ecs_service" "this" {
  name            = "auth-transformer"
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
