"""Tests for the effective launch of an MCP server entry (``_mcp_launch``)."""

from __future__ import annotations

import pytest

from threatcode.parsers._mcp_launch import (
    _RUN_BOOLEAN_OPTIONS,
    _RUN_VALUE_OPTIONS,
    MAX_UNWRAP_DEPTH,
    bind_mount_sources,
    classify_image,
    classify_npm_spec,
    classify_py_spec,
    container_flags,
    lacks_no_new_privileges,
    resolve_launch,
    scrub_userinfo,
    unpinned_packages,
)


def _unpinned(command: str, args: list[str]) -> list[tuple[str, str]]:
    return unpinned_packages(resolve_launch(command, args))


class TestLauncherForms:
    """Every launcher form reports the package that it really runs."""

    @pytest.mark.parametrize(
        ("command", "args", "runner", "package"),
        [
            ("npx", ["-y", "pkg"], "npx", "pkg"),
            ("npx.cmd", ["-y", "pkg"], "npx", "pkg"),
            ("/usr/local/bin/npx", ["pkg"], "npx", "pkg"),
            ("cmd", ["/c", "npx", "-y", "pkg"], "npx", "pkg"),
            ("cmd.exe", ["/s", "/c", "npx", "-y", "pkg"], "npx", "pkg"),
            ("cmd", ["/c", "npx -y pkg"], "npx", "pkg"),
            ("cmd", ["/k", "npx", "pkg"], "npx", "pkg"),
            ("powershell", ["-NoProfile", "-Command", "npx -y pkg"], "npx", "pkg"),
            ("pwsh", ["-c", "& npx -y pkg"], "npx", "pkg"),
            ("bash", ["-c", "npx -y pkg"], "npx", "pkg"),
            ("sh", ["-lc", "npx -y pkg"], "npx", "pkg"),
            ("zsh", ["-c", "cd /srv && npx -y pkg"], "npx", "pkg"),
            ("bash", ["-c", "source ~/.nvm/nvm.sh; exec npx -y pkg 2>&1"], "npx", "pkg"),
            ("env", ["FOO=1", "npx", "-y", "pkg"], "npx", "pkg"),
            ("env", ["-i", "-u", "X", "FOO=1", "BAR=2", "npx", "pkg"], "npx", "pkg"),
            ("env", ["-S", "npx -y pkg"], "npx", "pkg"),
            ("sudo", ["-u", "svc", "npx", "pkg"], "npx", "pkg"),
            ("nice", ["-n", "5", "npx", "pkg"], "npx", "pkg"),
            ("nohup", ["npx", "pkg"], "npx", "pkg"),
            ("exec", ["npx", "pkg"], "npx", "pkg"),
            ("command", ["-p", "npx", "pkg"], "npx", "pkg"),
            ("wsl", ["-d", "Ubuntu", "--", "npx", "-y", "pkg"], "npx", "pkg"),
            ("npm", ["exec", "-y", "pkg"], "npm exec", "pkg"),
            ("npm", ["exec", "--yes", "--", "pkg"], "npm exec", "pkg"),
            ("pnpm", ["exec", "pkg"], "pnpm exec", "pkg"),
            ("pnpm", ["dlx", "pkg"], "pnpm dlx", "pkg"),
            ("yarn", ["dlx", "pkg"], "yarn dlx", "pkg"),
            ("bun", ["x", "pkg"], "bun x", "pkg"),
            ("bunx", ["pkg"], "bunx", "pkg"),
            ("pipx", ["run", "mcp-server-foo"], "pipx run", "mcp-server-foo"),
            ("uv", ["tool", "run", "mcp-server-foo"], "uv tool run", "mcp-server-foo"),
            ("uvx", ["mcp-server-foo"], "uvx", "mcp-server-foo"),
            ("deno", ["run", "-A", "npm:pkg"], "deno", "pkg"),
            ("npx -y pkg", [], "npx", "pkg"),
        ],
    )
    def test_the_runner_and_package_behind_a_launcher(
        self, command: str, args: list[str], runner: str, package: str
    ) -> None:
        launch = resolve_launch(command, args)
        assert launch.runner == runner
        assert launch.package_name == package

    @pytest.mark.parametrize(
        ("command", "args"),
        [
            ("cmd", ["/c", "npx", "-y", "pkg"]),
            ("bash", ["-c", "npx -y pkg"]),
            ("env", ["FOO=1", "npx", "-y", "pkg"]),
            ("npm", ["exec", "-y", "pkg"]),
            ("pnpm", ["exec", "pkg"]),
            ("pipx", ["run", "pkg"]),
            ("uv", ["tool", "run", "pkg"]),
            ("deno", ["run", "-A", "npm:pkg"]),
            ("sudo", ["env", "A=1", "bash", "-c", "npx pkg"]),
        ],
    )
    def test_an_unpinned_package_behind_any_launcher_is_reported(
        self, command: str, args: list[str]
    ) -> None:
        found = _unpinned(command, args)
        assert len(found) == 1
        assert found[0][1] == "no-version"

    def test_a_pinned_package_behind_a_launcher_is_not_reported(self) -> None:
        assert _unpinned("cmd", ["/c", "npx", "-y", "pkg@1.2.3"]) == []
        assert _unpinned("bash", ["-c", "uvx pkg==1.2.3"]) == []

    def test_the_launchers_are_recorded_in_order(self) -> None:
        launch = resolve_launch("sudo", ["env", "A=1", "bash", "-c", "npx pkg"])
        assert launch.wrappers == ["sudo", "env", "bash"]
        assert launch.env_overrides == {"A": "1"}

    def test_a_python_module_is_the_package(self) -> None:
        launch = resolve_launch("python", ["-m", "tools_server", "--port", "1"])
        assert launch.package_name == "tools_server"
        assert [t.text for t in launch.server_args] == ["--port", "1"]

    def test_a_script_run_by_an_interpreter_has_no_package(self) -> None:
        launch = resolve_launch("node", ["/Users/me/projects/mcp-shell-docs/server.js"])
        assert launch.package_name == ""

    def test_an_empty_entry_resolves_to_nothing(self) -> None:
        launch = resolve_launch("", [])
        assert launch.runner == "" and launch.inner_argv == []

    def test_the_origin_of_each_word_is_the_original_argument_index(self) -> None:
        launch = resolve_launch("cmd", ["/c", "npx", "-y", "pkg", "--token", "x"])
        origins = {t.text: t.origin for t in launch.inner_argv}
        assert origins["pkg"] == 3
        assert origins["x"] == 5

    def test_words_from_a_shell_string_share_the_string_index(self) -> None:
        launch = resolve_launch("bash", ["-c", "npx -y pkg --token abc"])
        assert {t.origin for t in launch.inner_argv} == {1}
        assert launch.split_origins == {1}


class TestUnwrapDepth:
    def test_the_depth_cap_leaves_a_deeper_launcher_opaque(self) -> None:
        assert MAX_UNWRAP_DEPTH == 4
        four = resolve_launch("nohup", ["nohup", "nohup", "nohup", "npx", "pkg"])
        assert four.runner == "npx" and four.package_name == "pkg"
        five = resolve_launch("nohup", ["nohup", "nohup", "nohup", "nohup", "npx", "pkg"])
        assert five.runner == "nohup"
        assert five.package_name == "nohup"
        assert unpinned_packages(five) == []

    def test_a_shell_string_that_nests_shells_stops_at_the_cap(self) -> None:
        text = 'bash -c \'bash -c "bash -c \\"bash -c npx\\""\''
        launch = resolve_launch("bash", ["-c", text])
        assert len(launch.wrappers) <= MAX_UNWRAP_DEPTH


class TestBridges:
    def test_mcp_remote_lifts_the_url_and_the_header(self) -> None:
        launch = resolve_launch(
            "npx",
            [
                "-y",
                "mcp-remote@0.1.5",
                "http://host/sse",
                "--header",
                "Authorization: Bearer literal",
                "--allow-http",
            ],
        )
        assert launch.bridge == "mcp-remote"
        assert launch.remote_url == "http://host/sse"
        assert launch.remote_url_origin == 2
        assert launch.extra_headers == {"Authorization": "Bearer literal"}
        assert launch.allow_http is True

    def test_a_version_pinned_wrapper_name_is_recognised(self) -> None:
        launch = resolve_launch("npx", ["mcp-remote@0.1.12", "https://h/sse"])
        assert launch.bridge == "mcp-remote"
        assert launch.allow_http is False

    def test_supergateway_reads_the_sse_url(self) -> None:
        launch = resolve_launch(
            "npx", ["-y", "supergateway", "--sse", "https://h/sse", "--port", "1"]
        )
        assert launch.bridge == "supergateway"
        assert launch.remote_url == "https://h/sse"

    def test_supergateway_reads_the_streamable_http_url_and_a_bearer_flag(self) -> None:
        launch = resolve_launch(
            "npx",
            ["supergateway", "--streamableHttp", "https://h/mcp", "--oauth2Bearer", "tok123456"],
        )
        assert launch.remote_url == "https://h/mcp"
        assert launch.extra_headers == {"Authorization": "Bearer tok123456"}

    def test_supergateway_stdio_wraps_a_local_command_not_a_remote_server(self) -> None:
        launch = resolve_launch(
            "npx",
            ["-y", "supergateway", "--stdio", "npx -y @acme/files-mcp /srv", "--port", "8000"],
        )
        assert launch.bridge == ""
        assert launch.remote_url == ""
        assert launch.package_name == "@acme/files-mcp"
        assert "supergateway" in launch.wrappers

    def test_mcp_proxy_takes_header_name_and_value_as_two_arguments(self) -> None:
        launch = resolve_launch(
            "uvx", ["mcp-proxy", "https://h/sse", "--headers", "X-Api-Key", "k1234567"]
        )
        assert launch.bridge == "mcp-proxy"
        assert launch.remote_url == "https://h/sse"
        assert launch.extra_headers == {"X-Api-Key": "k1234567"}

    def test_a_server_that_is_not_a_bridge_lifts_nothing(self) -> None:
        launch = resolve_launch("npx", ["-y", "@acme/api-mcp", "https://h/x", "--header", "A: b"])
        assert launch.bridge == ""
        assert launch.remote_url == ""
        assert launch.extra_headers == {}


class TestDocker:
    def test_value_flags_before_the_image_are_skipped(self) -> None:
        launch = resolve_launch("docker", ["run", "-i", "--rm", "--memory", "512m", "img:1.0"])
        assert launch.image == "img:1.0"
        assert unpinned_packages(launch) == []

    def test_pull_always_is_not_the_image(self) -> None:
        launch = resolve_launch("docker", ["run", "--pull", "always", "ghcr.io/o/img:1.2"])
        assert launch.image == "ghcr.io/o/img:1.2"
        assert unpinned_packages(launch) == []

    def test_global_options_before_the_subcommand(self) -> None:
        launch = resolve_launch("docker", ["--context", "x", "run", "-i", "ghcr.io/o/img:1.0"])
        assert launch.image == "ghcr.io/o/img:1.0"
        by_host = resolve_launch("docker", ["-H", "ssh://h", "run", "-i", "img@sha256:abc"])
        assert by_host.image == "img@sha256:abc"
        configured = resolve_launch("docker", ["--config", "/c", "-D", "run", "ghcr.io/o/i:2.0"])
        assert configured.image == "ghcr.io/o/i:2.0"

    def test_container_run_is_the_same_as_run(self) -> None:
        launch = resolve_launch("docker", ["container", "run", "--rm", "ghcr.io/o/img:1.0"])
        assert launch.image == "ghcr.io/o/img:1.0"
        assert launch.container_subcommand == "container run"

    def test_podman_global_option_with_a_value(self) -> None:
        launch = resolve_launch("podman", ["--root", "/r", "run", "ghcr.io/o/img:1.0"])
        assert launch.image == "ghcr.io/o/img:1.0"

    def test_docker_exec_has_no_image_and_nothing_to_pin(self) -> None:
        launch = resolve_launch("docker", ["exec", "-i", "mycontainer", "node", "server.js"])
        assert launch.image == ""
        assert launch.container_subcommand == "exec"
        assert unpinned_packages(launch) == []

    def test_short_flag_clusters_and_attached_values(self) -> None:
        launch = resolve_launch(
            "docker", ["run", "-it", "-eA=1", "-v/a:/b", "-p8080:80", "-u", "root", "img:1.2"]
        )
        assert launch.image == "img:1.2"
        names = [o.name for o in launch.container_options]
        assert names == [
            "--interactive",
            "--tty",
            "--env",
            "--volume",
            "--publish",
            "--user",
        ]

    def test_an_unknown_flag_is_a_boolean_not_a_value_taking_flag(self) -> None:
        launch = resolve_launch("docker", ["run", "--some-future-flag", "img:1.2"])
        assert launch.image == "img:1.2"
        assert [(o.name, o.value) for o in launch.container_options] == [
            ("--some-future-flag", None)
        ]

    def test_the_option_tables_do_not_overlap(self) -> None:
        assert not _RUN_VALUE_OPTIONS & _RUN_BOOLEAN_OPTIONS

    @pytest.mark.parametrize(
        "flag",
        ["--memory", "--pull", "--cap-add", "--device", "--security-opt", "--user", "--volume"],
    )
    def test_value_taking_flags_are_in_the_table(self, flag: str) -> None:
        assert flag in _RUN_VALUE_OPTIONS

    @pytest.mark.parametrize("flag", ["--rm", "--privileged", "--init", "--interactive", "--tty"])
    def test_boolean_flags_are_in_the_table(self, flag: str) -> None:
        assert flag in _RUN_BOOLEAN_OPTIONS

    def test_the_container_command_after_the_image_is_not_read_as_options(self) -> None:
        launch = resolve_launch("docker", ["run", "img:1.0", "--privileged", "--user", "root"])
        assert container_flags(launch) == []
        assert [t.text for t in launch.server_args] == ["--privileged", "--user", "root"]


class TestContainerFlags:
    @pytest.mark.parametrize(
        ("flags", "expected"),
        [
            (["--privileged"], ["--privileged"]),
            (["--privileged=true"], ["--privileged"]),
            (["--privileged=false"], []),
            (["--privileged=0"], []),
            (["--network", "host"], ["--network=host"]),
            (["--net=host"], ["--network=host"]),
            (["--network=bridge"], []),
            (["--pid=host"], ["--pid=host"]),
            (["--pid", "host"], ["--pid=host"]),
            (["--userns=host"], ["--userns=host"]),
            (["--ipc", "host"], ["--ipc=host"]),
            (["--cap-add", "SYS_ADMIN"], ["--cap-add=SYS_ADMIN"]),
            (["--cap-add", "NET_ADMIN"], ["--cap-add=NET_ADMIN"]),
            (["--cap-add=BPF"], ["--cap-add=BPF"]),
            (["--cap-add=cap_net_raw"], ["--cap-add=NET_RAW"]),
            (["--cap-add", "ALL"], ["--cap-add=ALL"]),
            (["--cap-add", "NET_BIND_SERVICE"], []),
            (["--cap-drop=ALL"], []),
            (["--device", "/dev/mem"], ["--device=/dev/mem"]),
            (["--device=/dev/kmem:/dev/kmem"], ["--device=/dev/kmem"]),
            (["--device", "/dev/sda"], ["--device=/dev/sda"]),
            (["--user", "root"], ["--user=root"]),
            (["--user", "0"], ["--user=0"]),
            (["-u", "0:0"], ["--user=0:0"]),
            (["--user", "1000:1000"], []),
            (["--security-opt", "seccomp=unconfined"], ["--security-opt=seccomp=unconfined"]),
            (["--security-opt", "apparmor:unconfined"], ["--security-opt=apparmor=unconfined"]),
            (
                ["--security-opt", "no-new-privileges=false"],
                ["--security-opt=no-new-privileges=false"],
            ),
            (["--security-opt", "no-new-privileges"], []),
            (["--security-opt=no-new-privileges:true"], []),
        ],
    )
    def test_flag_table(self, flags: list[str], expected: list[str]) -> None:
        launch = resolve_launch("docker", ["run", "-i", "--rm", *flags, "img@sha256:abc"])
        assert container_flags(launch) == expected

    def test_absent_no_new_privileges_is_reported_only_as_informational(self) -> None:
        plain = resolve_launch("docker", ["run", "img@sha256:abc"])
        assert lacks_no_new_privileges(plain) is True
        assert container_flags(plain) == []
        hardened = resolve_launch(
            "docker", ["run", "--security-opt", "no-new-privileges", "img@sha256:abc"]
        )
        assert lacks_no_new_privileges(hardened) is False

    def test_a_non_run_subcommand_has_no_container_findings(self) -> None:
        launch = resolve_launch("docker", ["exec", "--privileged", "c", "sh"])
        assert container_flags(launch) == []
        assert lacks_no_new_privileges(launch) is False

    @pytest.mark.parametrize(
        ("args", "sources"),
        [
            (["-v", "/etc:/etc"], ["/etc"]),
            (["--volume=/Users/me:/projects:ro"], ["/Users/me"]),
            (["-v", "named-volume:/data"], []),
            (["-v", "C:\\Users\\me:/data"], ["C:\\Users\\me"]),
            (["--mount", "type=bind,source=/,target=/host"], ["/"]),
            (["--mount", "type=bind,src=/var/run,dst=/r"], ["/var/run"]),
            (["--mount", "type=volume,source=data,target=/d"], []),
            (["-v", "./local:/data"], ["./local"]),
        ],
    )
    def test_bind_mount_sources(self, args: list[str], sources: list[str]) -> None:
        launch = resolve_launch("docker", ["run", *args, "img:1.0"])
        assert bind_mount_sources(launch) == sources


class TestPinningPolicy:
    @pytest.mark.parametrize(
        ("spec", "status", "reason"),
        [
            ("pkg@1.2.3", "pinned", ""),
            ("@s/pkg@1.2.3", "pinned", ""),
            ("pkg@1.2.3-beta.1", "pinned", ""),
            ("pkg@^1.2.3", "unpinned", "range"),
            ("pkg@~1.2.3", "unpinned", "range"),
            ("pkg@>=1", "unpinned", "range"),
            ("pkg@1.x", "unpinned", "range"),
            ("pkg@1", "unpinned", "partial-version"),
            ("pkg@1.2", "unpinned", "partial-version"),
            ("pkg@beta", "unpinned", "dist-tag"),
            ("pkg@latest", "unpinned", "dist-tag"),
            ("@s/pkg@canary", "unpinned", "dist-tag"),
            ("pkg", "unpinned", "no-version"),
            ("@s/pkg", "unpinned", "no-version"),
            ("pkg@", "unpinned", "no-version"),
            ("github:u/r#v1.2.3", "pinned", ""),
            ("github:u/r#" + "a" * 40, "pinned", ""),
            ("github:u/r#main", "unpinned", "branch"),
            ("github:u/r", "unpinned", "git-no-ref"),
            ("u/r#v2.0.1", "pinned", ""),
            ("git+https://github.com/u/r.git#v1.0.0", "pinned", ""),
            ("git+https://github.com/u/r.git#develop", "unpinned", "branch"),
            ("github:u/r#semver:^1.0.0", "unpinned", "range"),
            ("https://host/pkg.tgz", "unpinned", "remote-url"),
            ("./server", "skip", ""),
            ("../x", "skip", ""),
            ("/opt/server", "skip", ""),
            ("file:./local", "skip", ""),
            ("C:\\srv\\x", "skip", ""),
            ("npm:pkg@1.2.3", "pinned", ""),
            ("npm:pkg", "unpinned", "no-version"),
        ],
    )
    def test_npm_specs(self, spec: str, status: str, reason: str) -> None:
        assert classify_npm_spec(spec) == (status, reason)

    @pytest.mark.parametrize(
        ("spec", "status", "reason"),
        [
            ("pkg==1.2.3", "pinned", ""),
            ("pkg[extra]==1.2.3", "pinned", ""),
            ("pkg===1.2.3", "pinned", ""),
            ("pkg@1.2.3", "pinned", ""),
            ("pkg==1.*", "unpinned", "range"),
            ("pkg>=1.2", "unpinned", "range"),
            ("pkg~=1.2", "unpinned", "range"),
            ("pkg<2", "unpinned", "range"),
            ("pkg@latest", "unpinned", "dist-tag"),
            ("pkg", "unpinned", "no-version"),
            ("git+https://h/o/r@" + "b" * 40, "pinned", ""),
            ("git+https://h/o/r@v1.0", "pinned", ""),
            ("git+https://h/o/r@main", "unpinned", "branch"),
            ("git+https://h/o/r", "unpinned", "git-no-ref"),
            ("git+ssh://git@github.com/o/r", "unpinned", "git-no-ref"),
            ("./local", "skip", ""),
            ("file:///x", "skip", ""),
        ],
    )
    def test_python_specs(self, spec: str, status: str, reason: str) -> None:
        assert classify_py_spec(spec) == (status, reason)

    @pytest.mark.parametrize(
        ("image", "status", "reason"),
        [
            ("img:1.4.2", "pinned", ""),
            ("ghcr.io/o/img:v0.5.0", "pinned", ""),
            ("img@sha256:" + "a" * 64, "pinned", ""),
            ("img:latest@sha256:" + "a" * 64, "pinned", ""),
            ("registry:5000/img:2.1.0", "pinned", ""),
            ("img:20250101", "pinned", ""),
            ("img", "unpinned", "no-tag"),
            ("img:latest", "unpinned", "floating-tag"),
            ("img:stable", "unpinned", "floating-tag"),
            ("ghcr.io/o/img:main", "unpinned", "floating-tag"),
            ("img:edge", "unpinned", "floating-tag"),
            ("img:nightly", "unpinned", "floating-tag"),
            ("registry:5000/img", "unpinned", "no-tag"),
            ("node:20", "unpinned", "floating-tag"),
            ("${REGISTRY}/img:1.0", "skip", ""),
        ],
    )
    def test_images(self, image: str, status: str, reason: str) -> None:
        assert classify_image(image) == (status, reason)

    def test_every_floating_tag_of_the_shared_list_is_unpinned(self) -> None:
        from threatcode.parsers.image_ref import FLOATING_TAGS

        for tag in FLOATING_TAGS:
            assert classify_image(f"img:{tag}")[0] == "unpinned", tag

    def test_reasons_travel_with_each_package(self) -> None:
        found = _unpinned("uvx", ["--from", "git+https://h/o/r@main", "--with", "extra", "r"])
        assert found == [("git+https://h/o/r@main", "branch"), ("extra", "no-version")]

    def test_a_local_target_is_never_reported(self) -> None:
        assert _unpinned("npx", ["./server"]) == []
        assert _unpinned("npx", ["file:./local"]) == []
        assert _unpinned("uvx", ["--from", "./pkg", "tool"]) == []

    def test_npx_package_flag_wins_over_the_binary_name(self) -> None:
        assert _unpinned("npx", ["-y", "-p", "pkg@1.0.0", "pkg-bin"]) == []
        assert _unpinned("npx", ["-y", "--package=pkg", "pkg-bin"]) == [("pkg", "no-version")]
        assert _unpinned("npx", ["-p", "a@1.0.0", "-p", "b", "run"]) == [("b", "no-version")]

    def test_uv_run_checks_only_its_with_packages(self) -> None:
        assert _unpinned("uv", ["run", "--with", "dep==1.0", "server.py"]) == []
        assert _unpinned("uv", ["run", "--with", "dep", "server.py"]) == [("dep", "no-version")]

    def test_a_direct_command_is_not_a_fetched_package(self) -> None:
        assert _unpinned("node", ["server.js"]) == []
        assert _unpinned("mcp-server-foo", []) == []

    def test_credentials_in_a_package_url_are_scrubbed_before_they_are_stored(self) -> None:
        found = _unpinned("uvx", ["--from", "git+https://tok:pw@github.com/o/r@main", "r"])
        assert found == [("git+https://[REDACTED]@github.com/o/r@main", "branch")]
        assert scrub_userinfo("plain-spec") == "plain-spec"
