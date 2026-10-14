"""The intermediate representation: what a scan models.

- `graph`: `InfraGraph`, built from parser output, with typed edges.
- `nodes`, `edges`: the node and edge types.
- `catalog`: the category and trust zone of each resource type, per provider family.
- `references`: resolves the references a parser found to the nodes they name.
- `addressing`: helpers for resource addresses and source locations.
- `enrich`: the step that adds context once the graph is built.
"""
