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
| `module_scopes.plan.json` | A root and a module `net` that each own an `aws_vpc.main` and an `aws_security_group.shared`, so a reference that binds to a namesake in the wrong module is visible: a module resource referencing its own VPC, an instance in the module receiving the root group through a variable, an instance receiving the module's own group, a root instance reading a module output, a nested module `net.leaf` that gets a root key through two variables and exposes a bucket output, and a `for_each` module `tenant["a"]` and `tenant["b"]` with an instance pinned to one key. |
| `unknown_values.plan.json` | CloudTrail trails and SQS queues with the encryption key known only after apply (`after_unknown`, with the reference in the configuration) beside trails and queues with no key at all, the same pair inside a module that receives the key as a variable, and a bucket whose provider-computed settings are all unknown. A rule that reads the missing key must stay quiet on the first kind and fire on the second. |
| `azure_network.plan.json` | The `azurerm` provider's shapes: a resource group referenced by name from every resource, a virtual network and subnet, a network security group with inline `security_rule` blocks (a list of objects with every key the provider writes), a standalone `azurerm_network_security_rule` open to the internet on RDP, a subnet association, and a network interface whose `ip_configuration[]` block references the subnet. |
| `gcp_network.plan.json` | The `google` provider's shapes: a VPC and subnetwork, two `google_compute_firewall` rules with `allow[]` blocks (one open to `0.0.0.0/0` on SSH), and an instance whose `network_interface[]` block references the network and subnetwork. Computed attributes such as `self_link` and the network of the subnetwork are unknown after apply. |

