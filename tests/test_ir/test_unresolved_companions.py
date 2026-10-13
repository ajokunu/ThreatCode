"""A companion whose target cannot be found must not silence findings elsewhere (RW-01).

One security group rule that points at a parameter, or one bucket setting that points at a
variable, used to turn the facts of every candidate parent in the whole scan into Unknown, so a
repository with a single such resource lost every ``SG_*`` and ``S3_NO_*`` finding, with no
coverage gap to say so.

These tests pin the three halves of the fix: a definite finding still fires next to an
unresolved companion, the unknown stays inside the input that wrote the companion, and every
place where it is applied is reported as a coverage gap.
Each scenario is written the way a repository writes it, as files in a directory.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.helpers.scan import ScanResult, scan_files
from threatcode.ir.graph import InfraGraph
from threatcode.parsers.base import ParsedOutput, ParsedResource
from threatcode.values import Unknown, is_unknown

GAP = "enrich.unresolved_companion"

OPEN_SG_TEMPLATE = """\
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  OpenSG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: ssh from anywhere
      VpcId: vpc-123
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: 0.0.0.0/0
"""


def _cfn_rule(name: str, group_id: str) -> str:
    return f"""\
AWSTemplateFormatVersion: "2010-09-09"
Parameters:
  OtherSG:
    Type: String
Resources:
  {name}:
    Type: AWS::EC2::SecurityGroupIngress
    Properties:
      GroupId: {group_id}
      IpProtocol: tcp
      FromPort: 443
      ToPort: 443
      CidrIp: 10.0.0.0/8
"""


def _scan(tmp_path: Path, files: dict[str, str]) -> ScanResult:
    paths = []
    for name, text in files.items():
        path = tmp_path / name
        path.write_text(text, encoding="utf-8")
        paths.append(path)
    return scan_files(paths)


POLICY = (
    '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*",'
    '"Action":"s3:GetObject","Resource":"*"}]}'
)


def _scan_module(tmp_path: Path, files: dict[str, str]) -> ScanResult:
    """Write the files into one directory and scan the directory, as one Terraform module."""
    for name, text in files.items():
        (tmp_path / name).write_text(text, encoding="utf-8")
    return scan_files([tmp_path])


def _gaps(graph: InfraGraph) -> list[str]:
    return [d.message for d in graph.diagnostics if d.code == GAP]


def _derived(graph: InfraGraph, node_id: str) -> dict[str, object]:
    derived = graph.nodes[node_id].properties.get("derived", {})
    assert isinstance(derived, dict)
    return derived


class TestACloudFormationParameterNamesNothingHere:
    """A ``Ref`` that is not a resource of the template is a parameter, so it is not a parent."""

    @pytest.mark.parametrize(
        "group_id",
        ["!Ref OtherSG", "!ImportValue SharedGroup", "!Select [0, !Ref OtherSG]"],
        ids=["parameter", "import", "select"],
    )
    def test_the_open_group_of_another_template_still_fires(
        self, tmp_path: Path, group_id: str
    ) -> None:
        result = _scan(tmp_path, {"a.yaml": OPEN_SG_TEMPLATE, "b.yaml": _cfn_rule("R", group_id)})
        assert result.fired("SG_UNRESTRICTED_INGRESS", "OpenSG")

    @pytest.mark.parametrize("group_id", ["!Ref OtherSG", "!ImportValue SharedGroup"])
    def test_no_gap_is_recorded_for_a_target_that_is_outside_the_scan(
        self, tmp_path: Path, group_id: str
    ) -> None:
        result = _scan(tmp_path, {"a.yaml": OPEN_SG_TEMPLATE, "b.yaml": _cfn_rule("R", group_id)})
        assert _gaps(result.graph) == []

    def test_a_ref_to_a_resource_of_another_template_is_not_followed(self, tmp_path: Path) -> None:
        # In b.yaml OpenSG is a parameter name; the resource of that name lives in a.yaml
        result = _scan(
            tmp_path,
            {
                "a.yaml": OPEN_SG_TEMPLATE,
                "b.yaml": _cfn_rule("R", "!Ref OpenSG").replace("OtherSG", "OpenSG"),
            },
        )
        derived = _derived(result.graph, "OpenSG")
        assert all(not is_unknown(rule) for rule in derived["ingress"])
        assert len(derived["ingress"]) == 1

    def test_a_ref_to_a_resource_of_the_same_template_is_folded(self, tmp_path: Path) -> None:
        text = (
            OPEN_SG_TEMPLATE.split("      SecurityGroupIngress:")[0]
            + """\
  Rule:
    Type: AWS::EC2::SecurityGroupIngress
    Properties:
      GroupId: !Ref OpenSG
      IpProtocol: tcp
      FromPort: 22
      ToPort: 22
      CidrIp: 0.0.0.0/0
"""
        )
        result = _scan(tmp_path, {"a.yaml": text})
        assert result.fired("SG_UNRESTRICTED_INGRESS", "OpenSG")
        assert _gaps(result.graph) == []


class TestADefiniteRuleSurvivesAnUnresolvedAddition:
    """A rule resource can only add ingress, so a world-open rule that is known still counts."""

    HCL_OPEN = """\
resource "aws_security_group" "open" {
  vpc_id = "vpc-1"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""
    HCL_UNRESOLVED_RULE = """\
variable "other_sg" {}
resource "aws_security_group_rule" "r" {
  type              = "ingress"
  security_group_id = var.other_sg
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["10.0.0.0/8"]
}
"""

    def test_the_open_inline_rule_still_fires(self, tmp_path: Path) -> None:
        result = _scan_module(tmp_path, {"a.tf": self.HCL_OPEN, "b.tf": self.HCL_UNRESOLVED_RULE})
        # Both files are one Terraform module, so the unresolved rule is a candidate for it
        assert result.fired("SG_UNRESTRICTED_INGRESS", "aws_security_group.open")

    def test_the_list_keeps_the_known_rule_and_one_unknown_entry(self, tmp_path: Path) -> None:
        result = _scan_module(tmp_path, {"a.tf": self.HCL_OPEN, "b.tf": self.HCL_UNRESOLVED_RULE})
        entries = _derived(result.graph, "aws_security_group.open")["ingress"]
        assert isinstance(entries, list)
        assert [e["cidr_blocks"] for e in entries if not is_unknown(e)] == [["0.0.0.0/0"]]
        assert sum(is_unknown(e) for e in entries) == 1

    def test_the_gap_names_the_rule_the_group_and_the_effect(self, tmp_path: Path) -> None:
        result = _scan_module(tmp_path, {"a.tf": self.HCL_OPEN, "b.tf": self.HCL_UNRESOLVED_RULE})
        (message,) = _gaps(result.graph)
        assert "aws_security_group_rule.r" in message
        assert "var.other_sg" in message
        assert "aws_security_group" in message
        assert "add entries to egress, ingress" in message or "add entries to ingress" in message
        (diagnostic,) = [d for d in result.graph.diagnostics if d.code == GAP]
        assert diagnostic.level == "warning"
        assert diagnostic.file.endswith("b.tf")
        assert diagnostic.line == 2

    def test_a_group_without_a_world_open_rule_is_not_reported(self, tmp_path: Path) -> None:
        closed = self.HCL_OPEN.replace("0.0.0.0/0", "10.0.0.0/8")
        result = _scan_module(tmp_path, {"a.tf": closed, "b.tf": self.HCL_UNRESOLVED_RULE})
        assert not result.fired("SG_UNRESTRICTED_INGRESS")


class TestAnAbsenceFactStaysUnknownInsideItsInput:
    """A setting that is missing cannot be told from one the scan cannot find: unknown, and said."""

    BUCKET = """\
resource "aws_s3_bucket" "data" {
  bucket = "my-data"
}
"""
    UNRESOLVED_ENCRYPTION = """\
variable "other_bucket" {}
resource "aws_s3_bucket_server_side_encryption_configuration" "x" {
  bucket = var.other_bucket
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}
"""

    def test_the_absence_finding_is_not_reported_in_the_same_module(self, tmp_path: Path) -> None:
        result = _scan_module(tmp_path, {"a.tf": self.BUCKET, "b.tf": self.UNRESOLVED_ENCRYPTION})
        assert not result.fired("S3_NO_ENCRYPTION", "aws_s3_bucket.data")

    def test_it_is_reported_as_a_coverage_gap(self, tmp_path: Path) -> None:
        result = _scan_module(tmp_path, {"a.tf": self.BUCKET, "b.tf": self.UNRESOLVED_ENCRYPTION})
        (message,) = _gaps(result.graph)
        assert "aws_s3_bucket" in message
        assert "sse_algorithm" in message
        assert "not reported" in message

    def test_the_other_settings_of_the_bucket_are_not_affected(self, tmp_path: Path) -> None:
        result = _scan_module(tmp_path, {"a.tf": self.BUCKET, "b.tf": self.UNRESOLVED_ENCRYPTION})
        assert result.fired("S3_NO_VERSIONING", "aws_s3_bucket.data")
        assert result.fired("S3_NO_LOGGING", "aws_s3_bucket.data")

    def test_a_bucket_of_another_input_is_not_affected(self, tmp_path: Path) -> None:
        other = tmp_path / "other"
        other.mkdir()
        (other / "main.tf").write_text(self.BUCKET, encoding="utf-8")
        mine = tmp_path / "mine"
        mine.mkdir()
        (mine / "main.tf").write_text(self.UNRESOLVED_ENCRYPTION, encoding="utf-8")
        result = scan_files([other, mine])
        assert result.fired("S3_NO_ENCRYPTION", "aws_s3_bucket.data")
        assert _gaps(result.graph) == []

    def test_a_companion_with_no_candidate_leaves_no_gap(self, tmp_path: Path) -> None:
        result = _scan_module(tmp_path, {"b.tf": self.UNRESOLVED_ENCRYPTION})
        assert _gaps(result.graph) == []

    def test_one_gap_per_companion_however_many_parents_it_might_configure(
        self, tmp_path: Path
    ) -> None:
        buckets = "".join(
            f'resource "aws_s3_bucket" "b{i}" {{\n  bucket = "bucket-{i}"\n}}\n' for i in range(5)
        )
        result = _scan_module(tmp_path, {"a.tf": buckets, "b.tf": self.UNRESOLVED_ENCRYPTION})
        (message,) = _gaps(result.graph)
        assert "any of the 5 aws_s3_bucket resources" in message
        for i in range(5):
            assert not result.fired("S3_NO_ENCRYPTION", f"aws_s3_bucket.b{i}")


class TestTheSameExpressionNamesTheSameResource:
    """A Sub-built name that two resources of one template share is one resource, not a guess."""

    TEMPLATE = """\
AWSTemplateFormatVersion: "2010-09-09"
Parameters:
  AppName:
    Type: String
Resources:
  Data:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Sub "${AppName}-data"
  Logs:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Sub "${AppName}-logs"
  DataPolicy:
    Type: AWS::S3::BucketPolicy
    Properties:
      Bucket: !Sub "${AppName}-data"
      PolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal: "*"
            Action: s3:GetObject
            Resource: !Sub "arn:aws:s3:::${AppName}-data/*"
"""

    def test_the_policy_is_folded_into_the_bucket_of_that_name(self, tmp_path: Path) -> None:
        result = _scan(tmp_path, {"a.yaml": self.TEMPLATE})
        data = _derived(result.graph, "Data")["policy_statements"]
        logs = _derived(result.graph, "Logs")["policy_statements"]
        assert isinstance(data, list) and len(data) == 1
        assert logs == []

    def test_no_gap_is_recorded_when_the_expression_decides(self, tmp_path: Path) -> None:
        result = _scan(tmp_path, {"a.yaml": self.TEMPLATE})
        assert _gaps(result.graph) == []

    def test_a_different_expression_is_not_assumed_to_match(self, tmp_path: Path) -> None:
        text = self.TEMPLATE.replace(
            'Bucket: !Sub "${AppName}-data"', 'Bucket: !Sub "${AppName}-elsewhere"'
        )
        result = _scan(tmp_path, {"a.yaml": text})
        assert len(_gaps(result.graph)) == 1
        assert is_unknown(_derived(result.graph, "Data")["policy_statements"])
        assert is_unknown(_derived(result.graph, "Logs")["policy_statements"])

    def test_module_calls_with_different_variables_do_not_share_an_expression(self) -> None:
        # The two buckets read the same text, but each module is called with its own prefix
        def bucket(module: str) -> ParsedResource:
            return ParsedResource(
                resource_type="aws_s3_bucket",
                address=f"{module}.aws_s3_bucket.b",
                name="b",
                provider="aws",
                module=module,
                properties={"bucket": Unknown("${var.prefix}-data")},
            )

        def policy() -> ParsedResource:
            return ParsedResource(
                resource_type="aws_s3_bucket_policy",
                address="module.one.aws_s3_bucket_policy.p",
                name="p",
                provider="aws",
                module="module.one",
                properties={"bucket": Unknown("${var.prefix}-data"), "policy": POLICY},
            )

        graph = InfraGraph.from_parsed(
            ParsedOutput(
                resources=[bucket("module.one"), bucket("module.two"), policy()],
                format_type="terraform_hcl",
            )
        )
        one = _derived(graph, "module.one.aws_s3_bucket.b")["policy_statements"]
        two = _derived(graph, "module.two.aws_s3_bucket.b")["policy_statements"]
        assert isinstance(one, list) and not is_unknown(one)
        assert two == []


class TestTheGapReachesTheCommandLine:
    """A finding the scan cannot report must be visible, and --strict must count it."""

    MODULE = {
        "a.tf": TestAnAbsenceFactStaysUnknownInsideItsInput.BUCKET,
        "b.tf": TestAnAbsenceFactStaysUnknownInsideItsInput.UNRESOLVED_ENCRYPTION,
    }

    def _write(self, tmp_path: Path) -> Path:
        for name, text in self.MODULE.items():
            (tmp_path / name).write_text(text, encoding="utf-8")
        return tmp_path

    def test_the_gap_is_in_the_report_and_on_stderr_even_with_quiet(self, tmp_path: Path) -> None:
        from tests.helpers.cli import run_cli

        run = run_cli(["-q", "scan", str(self._write(tmp_path)), "-f", "json", "--fail-on", "none"])
        assert run.exit_code == 0
        gaps = [g for g in run.json()["coverage"]["gaps"] if g["code"] == GAP]
        assert len(gaps) == 1 and gaps[0]["file"] == "b.tf"
        assert "enrich.unresolved_companion" in run.stderr

    def test_strict_turns_the_gap_into_a_failure(self, tmp_path: Path) -> None:
        from tests.helpers.cli import run_cli

        path = str(self._write(tmp_path))
        assert run_cli(["scan", path, "-f", "json", "--strict"]).exit_code == 2
        assert run_cli(["scan", path, "-f", "json", "--fail-on", "none"]).exit_code == 0
