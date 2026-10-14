"""Enrichment modules: one per provider family, discovered by `threatcode.ir.enrich`.

Every public module of this package is imported in sorted name order and may export
``COMPANIONS``, ``DERIVERS``, ``RELATIONS`` and ``DEFAULTS``; `threatcode.ir.enrich` documents
what each one means and the order the phases run in.

``companions`` holds the cross-provider core: split S3 resources, flow logs, diagnostics, audit
policies, IAM attachments, security group rules and the policy documents of every
policy-bearing resource.
``relations`` holds the facts compute resources inherit from their roles.
A provider rule package adds its own module here (for example ``aws_network.py``) and never edits
these two.
Names that start with an underscore are helpers and are not discovered.
"""
