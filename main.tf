provider "aws" {
  profile = "aws-profile"
  region  = var.region
}

data "aws_availability_zones" "available" {
  filter {
    name   = "opt-in-status"
    values = ["opt-in-not-required"]
  }
}

locals {
  cluster_name = "log-clean-up-k8s-cluster"
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.0.0"

  name = "log-clean-up-vpc"

  cidr = "10.0.0.0/16"
  azs  = slice(data.aws_availability_zones.available.names, 0, 3)

  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets  = ["10.0.4.0/24", "10.0.5.0/24", "10.0.6.0/24"]

  enable_nat_gateway   = true
  single_nat_gateway   = true
  enable_dns_hostnames = true

  public_subnet_tags = {
    "kubernetes.io/cluster/${local.cluster_name}" = "shared"
    "kubernetes.io/role/elb"                      = 1
    "administrator"                               = "marco.terrinoni@spindox.it"
    "project-name"                                = "log-clean-up"
    "scope"                                       = "poc"
  }

  private_subnet_tags = {
    "kubernetes.io/cluster/${local.cluster_name}" = "shared"
    "kubernetes.io/role/internal-elb"             = 1
    "administrator"                               = "marco.terrinoni@spindox.it"
    "project-name"                                = "log-clean-up"
    "scope"                                       = "poc"
  }
}

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "19.15.3"

  cluster_name    = local.cluster_name
  cluster_version = "1.27"

  vpc_id                         = module.vpc.vpc_id
  subnet_ids                     = module.vpc.private_subnets
  cluster_endpoint_public_access = true

  eks_managed_node_group_defaults = {
    ami_type = "AL2_x86_64"

  }

  eks_managed_node_groups = {
    one = {
      name = "log-clean-up"

      instance_types = ["t3.small"]

      min_size     = 1
      max_size     = 1
      desired_size = 1
    }
  }

  tags = {
    "administrator" = "marco.terrinoni@spindox.it"
    "project-name"  = "log-clean-up"
    "scope"         = "poc"
  }
}

data "aws_iam_policy" "ebs_csi_policy" {
  arn = "arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"
}

module "irsa-ebs-csi" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-assumable-role-with-oidc"
  version = "4.7.0"

  create_role                   = true
  role_name                     = "AmazonEKSTFEBSCSIRole-${module.eks.cluster_name}"
  provider_url                  = module.eks.oidc_provider
  role_policy_arns              = [data.aws_iam_policy.ebs_csi_policy.arn]
  oidc_fully_qualified_subjects = ["system:serviceaccount:kube-system:ebs-csi-controller-sa"]
}

resource "aws_eks_addon" "ebs-csi" {
  cluster_name             = module.eks.cluster_name
  addon_name               = "aws-ebs-csi-driver"
  addon_version            = "v1.20.0-eksbuild.1"
  service_account_role_arn = module.irsa-ebs-csi.iam_role_arn
  tags = {
    "eks_addon"     = "ebs-csi"
    "terraform"     = "true"
    "administrator" = "marco.terrinoni@spindox.it"
    "project-name"  = "log-clean-up"
    "scope"         = "poc"
  }
}

resource "aws_cloudwatch_log_group" "eks_log_group" {
  name = "/aws/eks/${local.cluster_name}"

  tags = {
    "administrator" = "marco.terrinoni@spindox.it"
    "project-name"  = "log-clean-up"
    "scope"         = "poc"
  }
}

resource "aws_cloudwatch_log_group" "containerinsights_application_log_group" {
  name = "/aws/containerinsights/${local.cluster_name}/application"

  tags = {
    "administrator" = "marco.terrinoni@spindox.it"
    "project-name"  = "log-clean-up"
    "scope"         = "poc"
  }
}

resource "aws_cloudwatch_log_group" "containerinsights_dataplane_log_group" {
  name = "/aws/containerinsights/${local.cluster_name}/dataplane"

  tags = {
    "administrator" = "marco.terrinoni@spindox.it"
    "project-name"  = "log-clean-up"
    "scope"         = "poc"
  }
}

resource "aws_cloudwatch_log_group" "containerinsights_host_log_group" {
  name = "/aws/containerinsights/${local.cluster_name}/host"

  tags = {
    "administrator" = "marco.terrinoni@spindox.it"
    "project-name"  = "log-clean-up"
    "scope"         = "poc"
  }
}

resource "aws_cloudwatch_log_group" "containerinsights_performance_log_group" {
  name = "/aws/containerinsights/${local.cluster_name}/performance"

  tags = {
    "administrator" = "marco.terrinoni@spindox.it"
    "project-name"  = "log-clean-up"
    "scope"         = "poc"
  }
}

module "s3_bucket" {
  source = "terraform-aws-modules/s3-bucket/aws"

  bucket = "log-clean-up-bucket"
  acl    = "private"

  force_destroy = true

  control_object_ownership = true
  object_ownership         = "ObjectWriter"

  tags = {
    "administrator" = "marco.terrinoni@spindox.it"
    "project-name"  = "log-clean-up"
    "scope"         = "poc"
  }
}

resource "aws_s3_bucket_policy" "allow_access_from_cloudwatch" {
  bucket = module.s3_bucket.s3_bucket_id
  policy = data.aws_iam_policy_document.allow_access_from_cloudwatch.json
}

data "aws_iam_policy_document" "allow_access_from_cloudwatch" {
  statement {
    principals {
      type        = "Service"
      identifiers = ["logs.eu-central-1.amazonaws.com"]
    }

    actions = [
      "s3:GetBucketAcl"
    ]

    resources = [
      "${module.s3_bucket.s3_bucket_arn}"
    ]

    condition {
      test     = "ArnLike"
      values   = ["arn:aws:logs:${var.region}:${var.aws_account_id}:log-group:${aws_cloudwatch_log_group.containerinsights_application_log_group.name}:*"]
      variable = "aws:SourceArn"
    }
  }

  statement {
    principals {
      type        = "Service"
      identifiers = ["logs.eu-central-1.amazonaws.com"]
    }

    actions = [
      "s3:PutObject"
    ]

    resources = [
      "${module.s3_bucket.s3_bucket_arn}/*"
    ]

    condition {
      test     = "ArnLike"
      values   = ["arn:aws:logs:${var.region}:${var.aws_account_id}:log-group:${aws_cloudwatch_log_group.containerinsights_application_log_group.name}:*"]
      variable = "aws:SourceArn"
    }
  }
}

resource "aws_iam_user" "cwlogexport-robot-user" {
  name = "cwlogexport-robot-user"

  tags = {
    "administrator" = "marco.terrinoni@spindox.it"
    "project-name"  = "log-clean-up"
    "scope"         = "poc"
  }
}

resource "aws_iam_role" "log-clean-up-user-role" {
  name = "log-clean-up-user-role"

  assume_role_policy = data.aws_iam_policy_document.trust-policy.json
  
  tags = {
    "administrator" = "marco.terrinoni@spindox.it"
    "project-name"  = "log-clean-up"
    "scope"         = "poc"
  }
}

data "aws_iam_policy_document" "trust-policy" {
  statement {
    actions = ["sts:AssumeRole"]
    effect  = "Allow"

    principals {
      type        = "AWS"
      identifiers = [aws_iam_user.cwlogexport-robot-user.arn]
    }
  }
}

data "aws_iam_policy_document" "cwlogexport-policy-text" {
  statement {
    actions = [
      "logs:CreateExportTask",
      "logs:Describe*",
      "logs:ListTagsLogGroup"
    ]

    effect = "Allow"

    resources = [
      "*"
    ]
  }

  statement {
    actions = [
      "ssm:DescribeParameters",
      "ssm:GetParameter",
      "ssm:GetParameters",
      "ssm:GetParametersByPath",
      "ssm:PutParameter"
    ]

    effect = "Allow"

    resources = [
      "*"
    ]
  }

  statement {
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]

    effect = "Allow"

    resources = [
      "arn:aws:logs:${var.region}:${var.aws_account_id}:log-group:${aws_cloudwatch_log_group.containerinsights_application_log_group.name}:*"
    ]
  }

  statement {
    sid = "AllowCrossAccountObjectAcc"
    actions = [
      "s3:PutObject",
      "s3:PutObjectACL"
    ]

    effect = "Allow"

    resources = [
      "${module.s3_bucket.s3_bucket_arn}/*"
    ]
  }

  statement {
    sid    = "AllowCrossAccountBucketAcc"
    effect = "Allow"
    actions = [
      "s3:PutBucketAcl",
      "s3:GetBucketAcl"
    ]
    resources = ["${module.s3_bucket.s3_bucket_arn}"]
  }
}

resource "aws_iam_policy" "cwlogexport-policy" {
  name        = "cwlogexport-policy"
  description = "Policy that contains all the permissions to allow log exports"
  
  policy = data.aws_iam_policy_document.cwlogexport-policy-text.json
}

resource "aws_iam_policy_attachment" "log-clean-up-user-role-policy-attachment" {
  name = "log-clean-up-user-role-policy-attachment"
  policy_arn = aws_iam_policy.cwlogexport-policy.arn
  roles      = [aws_iam_role.log-clean-up-user-role.name]
}
