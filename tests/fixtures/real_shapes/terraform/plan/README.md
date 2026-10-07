# Terraform plan JSON

Source shape: `terraform show -json <planfile>`, `format_version` 1.2.
source: handbuilt (Terraform 1.9.5 and AWS provider 5.x shapes, written from the documented JSON schema; no binary was available).

What makes these real shapes:

* `planned_values` omits every attribute that is unknown until apply (ids, ARNs, attributes derived from other resources).
* `resource_changes[].change.after_unknown` lists those attributes, with nested booleans mirroring block shapes.
* `configuration.root_module.resources[].expressions` carries `references` for relationships, with both `aws_vpc.main.id` and `aws_vpc.main` listed as Terraform does.
* Nested blocks (`ingress`, `vpc_config`, `route`, `metadata_options`) are lists of objects in values and lists of expression objects in configuration.
* `count` and `for_each` produce one planned instance per index (`aws_instance.app[0]`, `aws_security_group_rule.ingress["https"]`) and a single configuration entry with `count_expression` or `for_each_expression`.
* Data sources appear in `prior_state` when read at plan time and in `planned_values` with a `read` action when deferred.

| File | Contents |
| --- | --- |
| `webapp.plan.json` | VPC, two public and two private subnets (counted), internet gateway, public route table, ALB, load balancer security group open to the internet, app security group reachable from the ALB group, database security group reachable from the app group, counted app instances with an instance profile and role, RDS in private subnets, AWS provider v4+ split S3 resources, Lambda with `vpc_config`, Secrets Manager secret, two data sources. |
| `modules.plan.json` | A counted module (`module.subnets[0]`, `module.subnets[1]`) with inputs from the root VPC and an output read by a root instance, a plain child module whose output feeds a root flow log, and a `for_each` security group rule. |
| `two_vpcs.plan.json` | Two VPCs, each with its own subnet, security group and instance, so any first-VPC shortcut puts resources in the wrong network. |
