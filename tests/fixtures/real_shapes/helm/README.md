# Helm

Source shape: charts on disk.
source: `scaffold/` is the output of `helm create scaffold` (Helm 3.15 template set, including `_helpers.tpl`, `NOTES.txt` and `templates/tests/`); `platform/` is hand-written.

| Path | Contents |
| --- | --- |
| `scaffold/` | The `helm create` chart: Deployment, Service, ServiceAccount, Ingress (disabled by default), HorizontalPodAutoscaler (disabled by default), `include` helpers, `toYaml | nindent`, `with` and `range` blocks and a test hook Pod. |
| `platform/` | A chart with templates in subdirectories (`templates/rbac/`, `templates/network/`) and a subchart under `charts/redis/` with its own `Chart.yaml`, `values.yaml` and templates, plus parent values that override the subchart. |
