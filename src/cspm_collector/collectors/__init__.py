"""Collector plugins. Importing a module registers its collector."""


def load_all() -> None:
    from . import autoscaling, awslambda, ec2, generic, iam, misc, route53, s3, sqs  # noqa: F401
