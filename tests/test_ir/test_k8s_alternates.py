"""Kubernetes objects of the same name in several files are alternates, not one deployment (RW-05).

A repository often holds one application several times: raw manifests, a Kustomize base, a
rendered release and a Helm chart.
Each defines the same Service and the same Deployment.
The reachability layer joins manifests across files, so every Service used to reach the
same-named Deployment of every variant, and a scan of four variants reported sixteen edges where
four exist.
These tests write the layouts the way repositories do and read the edges the graph holds.
"""

from __future__ import annotations

from pathlib import Path

from tests.helpers.scan import ScanResult, scan_files
from threatcode.ir.edges import EdgeType, InfraEdge

SERVICE = """\
apiVersion: v1
kind: Service
metadata:
  name: frontend-external
spec:
  type: LoadBalancer
  selector:
    app: frontend
  ports:
    - port: 80
      targetPort: 8080
"""

DEPLOYMENT = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: frontend
spec:
  selector:
    matchLabels:
      app: frontend
  template:
    metadata:
      labels:
        app: frontend
    spec:
      containers:
        - name: server
          image: example/frontend:1.0
"""


def _write(root: Path, files: dict[str, str]) -> list[Path]:
    paths = []
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        paths.append(path)
    return paths


def _selects(result: ScanResult) -> list[tuple[str, str]]:
    """(file of the Service, file of the workload) for every Service-to-workload edge."""
    found = []
    for edge in result.graph.edges:
        if edge.relation == "selects" and edge.edge_type is EdgeType.NETWORK_FLOW:
            source = result.graph.nodes[edge.source]
            target = result.graph.nodes[edge.target]
            found.append(
                (source.source_file.rsplit("/", 1)[-1], target.source_file.rsplit("/", 1)[-1])
            )
    return sorted(found)


def _edges(result: ScanResult, relation: str) -> list[InfraEdge]:
    return [edge for edge in result.graph.edges if edge.relation == relation]


class TestVariantsOfOneApplication:
    VARIANTS = ("raw", "kustomize", "release", "chart")

    def _variants(self, tmp_path: Path) -> ScanResult:
        files = {f"{name}/app.yaml": SERVICE + "---\n" + DEPLOYMENT for name in self.VARIANTS}
        return scan_files(_write(tmp_path, files))

    def test_each_variant_links_its_own_service_to_its_own_workload(self, tmp_path: Path) -> None:
        result = self._variants(tmp_path)
        edges = _edges(result, "selects")
        assert len(edges) == len(self.VARIANTS)
        for edge in edges:
            source = result.graph.nodes[edge.source]
            target = result.graph.nodes[edge.target]
            assert source.source_file == target.source_file

    def test_no_edge_joins_two_variants(self, tmp_path: Path) -> None:
        result = self._variants(tmp_path)
        files = {
            (result.graph.nodes[e.source].source_file, result.graph.nodes[e.target].source_file)
            for e in result.graph.edges
            if e.edge_type is EdgeType.NETWORK_FLOW and e.source != "internet"
        }
        assert all(first == second for first, second in files)

    def test_the_boundary_findings_are_one_per_variant(self, tmp_path: Path) -> None:
        result = self._variants(tmp_path)
        crossings = [
            t
            for t in result.threats
            if t.source.value == "boundary" and "frontend-external" in t.resource_address
        ]
        # internet -> Service and Service -> Deployment, once for each variant
        assert len(crossings) == 2 * len(self.VARIANTS)

    def test_the_internet_reaches_every_variant_of_the_service(self, tmp_path: Path) -> None:
        result = self._variants(tmp_path)
        entries = [e for e in result.graph.edges if e.source == "internet"]
        assert len(entries) == len(self.VARIANTS)


class TestManifestsSplitAcrossFiles:
    """A Service and the Deployment it selects often live in separate files of one directory."""

    def test_a_service_reaches_the_workload_of_another_file(self, tmp_path: Path) -> None:
        paths = _write(tmp_path, {"service.yaml": SERVICE, "deployment.yaml": DEPLOYMENT})
        assert _selects(scan_files(paths)) == [("service.yaml", "deployment.yaml")]

    def test_a_namespace_defined_in_both_files_does_not_make_them_alternates(
        self, tmp_path: Path
    ) -> None:
        namespace = "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: shop\n---\n"
        service = SERVICE.replace("name: frontend-external", "name: web\n  namespace: shop")
        deployment = DEPLOYMENT.replace("name: frontend", "name: frontend\n  namespace: shop", 1)
        paths = _write(
            tmp_path,
            {"service.yaml": namespace + service, "deployment.yaml": namespace + deployment},
        )
        assert _selects(scan_files(paths)) == [("service.yaml", "deployment.yaml")]

    def test_a_kustomize_base_joins_its_own_files_beside_an_overlay_patch(
        self, tmp_path: Path
    ) -> None:
        patch = DEPLOYMENT.replace("image: example/frontend:1.0", "image: example/frontend:2.0")
        paths = _write(
            tmp_path,
            {
                "base/service.yaml": SERVICE,
                "base/deployment.yaml": DEPLOYMENT,
                "overlays/prod/deployment.yaml": patch,
            },
        )
        links = _selects(scan_files(paths))
        assert ("service.yaml", "deployment.yaml") in links


class TestTwoServicesOfOneNameThatShareAWorkload:
    """minio: a standalone and a distributed install, with the same labels on both workloads."""

    def test_neither_variant_of_the_service_claims_the_workloads(self, tmp_path: Path) -> None:
        statefulset = DEPLOYMENT.replace("kind: Deployment", "kind: StatefulSet").replace(
            "name: frontend", "name: frontend-sts"
        )
        paths = _write(
            tmp_path,
            {
                "standalone-service.yaml": SERVICE,
                "distributed-service.yaml": SERVICE,
                "standalone-deployment.yaml": DEPLOYMENT,
                "distributed-statefulset.yaml": statefulset,
            },
        )
        assert _selects(scan_files(paths)) == []

    def test_a_service_with_no_twin_keeps_its_links(self, tmp_path: Path) -> None:
        statefulset = DEPLOYMENT.replace("kind: Deployment", "kind: StatefulSet").replace(
            "name: frontend", "name: frontend-sts"
        )
        paths = _write(
            tmp_path,
            {
                "service.yaml": SERVICE,
                "deployment.yaml": DEPLOYMENT,
                "statefulset.yaml": statefulset,
            },
        )
        assert _selects(scan_files(paths)) == [
            ("service.yaml", "deployment.yaml"),
            ("service.yaml", "statefulset.yaml"),
        ]

    def test_a_twin_workload_in_the_services_own_file_is_still_joined(self, tmp_path: Path) -> None:
        paths = _write(
            tmp_path,
            {
                "standalone.yaml": SERVICE + "---\n" + DEPLOYMENT,
                "distributed.yaml": SERVICE + "---\n" + DEPLOYMENT,
            },
        )
        assert _selects(scan_files(paths)) == [
            ("distributed.yaml", "distributed.yaml"),
            ("standalone.yaml", "standalone.yaml"),
        ]


class TestReferencesByNameResolveInsideTheVariant:
    INGRESS = """\
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: web
spec:
  rules:
    - http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: frontend-external
                port:
                  number: 80
"""

    def test_an_ingress_reaches_the_service_of_its_own_variant(self, tmp_path: Path) -> None:
        files = {f"{n}/app.yaml": self.INGRESS + "---\n" + SERVICE for n in ("one", "two", "three")}
        result = scan_files(_write(tmp_path, files))
        backends = _edges(result, "backend")
        assert len(backends) == 3
        for edge in backends:
            first = result.graph.nodes[edge.source].source_file
            second = result.graph.nodes[edge.target].source_file
            assert first == second

    def test_an_ingress_reaches_a_service_defined_once_in_another_file(
        self, tmp_path: Path
    ) -> None:
        paths = _write(tmp_path, {"ingress.yaml": self.INGRESS, "service.yaml": SERVICE})
        backends = _edges(scan_files(paths), "backend")
        assert len(backends) == 1

    def test_an_ingress_with_a_service_in_two_unrelated_files_has_no_backend(
        self, tmp_path: Path
    ) -> None:
        paths = _write(
            tmp_path,
            {
                "ingress.yaml": self.INGRESS,
                "a/service.yaml": SERVICE,
                "b/service.yaml": SERVICE,
            },
        )
        # Two copies of the Service, and the ingress shares an input with neither: open
        assert _edges(scan_files(paths), "backend") == []
