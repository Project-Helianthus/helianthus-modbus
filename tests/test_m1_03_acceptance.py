from __future__ import annotations

import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "validate_m1_03_acceptance.py"
SPEC = importlib.util.spec_from_file_location("validate_m1_03_acceptance", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)


def authorization_body() -> str:
    return "\n".join(
        (
            "<!-- execution-authorization:v1 -->",
            "plan_repo: Project-Helianthus/helianthus-execution-plans",
            (
                "plan_path: fronius-modbus-multivendor-v3-w29-26."
                "locked/plan.yaml"
            ),
            (
                "authorization_pr: https://github.com/Project-Helianthus/"
                "helianthus-execution-plans/pull/72"
            ),
            (
                "plan_head_sha: "
                "0576544bd8851c4e32da3ca7c401270eee43ef5c"
            ),
            (
                "authorized_issue_contract_sha256: "
                "e2700e6da559b851fef6b9d510033f1f9b9004964d19cb8c136885c78e7da8a5"
            ),
            "authorized_issue: FMV3-M1-03",
        )
    )


def authorization_payload() -> dict[str, object]:
    return {
        "id": 5084046075,
        "body": authorization_body(),
        "user": {"login": "d3vi1"},
        "author_association": "MEMBER",
        "created_at": "2026-07-26T15:04:11Z",
        "updated_at": "2026-07-26T15:04:11Z",
        "issue_url": (
            "https://api.github.com/repos/Project-Helianthus/"
            "helianthus-execution-plans/issues/71"
        ),
        "html_url": (
            "https://github.com/Project-Helianthus/"
            "helianthus-execution-plans/issues/71#issuecomment-5084046075"
        ),
    }


def transport_override_body() -> str:
    return "\n".join(
        (
            (
                "<!-- transport-gate-override: M1-03 is an offline fixture-only "
                "Modbus RTU transport implementation in a new repository; the "
                "eBUS T01..T88 baseline is not behaviorally applicable and no "
                "gateway, physical serial, or hardware path exists. The "
                "milestone-specific nine-row RTU abandonment/quarantine matrix "
                "is the required replacement gate. This override does not "
                "qualify, enable, or support physical RTU. -->"
            ),
            "",
            "- milestone: `FMV3-M1-03`",
            "- disposition: `FIXTURE_ONLY_NO_HARDWARE`",
            (
                "- replacement matrix: "
                "`policy/m1-03-transport-matrix.json`"
            ),
            (
                "- deferred boundary: physical RTU qualification remains "
                "a separate gate"
            ),
            (
                "- gateway boundary: no gateway integration or validation "
                "is included"
            ),
        )
    )


def transport_override_payload() -> dict[str, object]:
    return {
        "id": 5106470845,
        "body": transport_override_body(),
        "user": {"login": "d3vi1"},
        "author_association": "MEMBER",
        "created_at": "2026-07-28T15:54:47Z",
        "updated_at": "2026-07-28T15:54:47Z",
        "issue_url": (
            "https://api.github.com/repos/Project-Helianthus/"
            "helianthus-modbus/issues/9"
        ),
        "html_url": (
            "https://github.com/Project-Helianthus/helianthus-modbus/"
            "issues/9#issuecomment-5106470845"
        ),
    }


class M103AcceptanceTests(unittest.TestCase):
    def test_exact_manifest_validates_without_hosted_queries(self) -> None:
        document = json.loads(
            (ROOT / "policy" / "m1-03-acceptance.json").read_text(
                encoding="utf-8"
            )
        )
        plan = validator.base.read_git_blob(
            validator.PLAN_SOURCE["repository"],
            validator.PLAN_SOURCE["commit_sha"],
            validator.PLAN_SOURCE["path"],
        )
        count = validator.validate(
            ROOT,
            document,
            plan_bytes=plan,
            authorization_payload=authorization_payload(),
            verify_hosted=False,
            require_published=False,
            execute_tests=False,
        )
        self.assertGreater(count, 0)

    def test_authorization_field_drift_is_rejected(self) -> None:
        payload = authorization_payload()
        payload["body"] = authorization_body().replace(
            "authorized_issue: FMV3-M1-03",
            "authorized_issue: FMV3-M4-01",
        )
        with self.assertRaises(validator.AcceptanceError):
            validator.validate_authorization(payload)

    def test_authorization_metadata_drift_is_rejected(self) -> None:
        payload = authorization_payload()
        payload["author_association"] = "CONTRIBUTOR"
        validator.validate_authorization(payload)
        payload["author_association"] = "NONE"
        with self.assertRaises(validator.AcceptanceError):
            validator.validate_authorization(payload)

    def test_transport_override_body_and_author_are_immutable(self) -> None:
        payload = transport_override_payload()
        validator.validate_transport_override_payload(payload)
        payload["author_association"] = "CONTRIBUTOR"
        validator.validate_transport_override_payload(payload)
        payload["body"] = transport_override_body() + "\nrevoked"
        with self.assertRaises(validator.AcceptanceError):
            validator.validate_transport_override_payload(payload)

    def test_transport_matrix_requires_every_offline_rtu_row(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            relative = Path("policy/m1-03-transport-matrix.json")
            target = root / relative
            target.parent.mkdir(parents=True)
            shutil.copy2(ROOT / relative, target)
            document = {
                "gates": {
                    "transport_gate": {
                        "matrix_path": relative.as_posix(),
                        "matrix_sha256": validator.base.sha256(
                            target.read_bytes()
                        ),
                    }
                }
            }
            self.assertTrue(
                validator.validate_transport_matrix(root, document)
            )
            matrix = json.loads(target.read_text(encoding="utf-8"))
            matrix["rows"].pop()
            target.write_text(json.dumps(matrix), encoding="utf-8")
            document["gates"]["transport_gate"]["matrix_sha256"] = (
                validator.base.sha256(target.read_bytes())
            )
            with self.assertRaises(validator.AcceptanceError):
                validator.validate_transport_matrix(root, document)

    def test_offline_surface_rejects_physical_writer(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            policy = json.loads(
                (ROOT / "policy" / "phase1-readonly.json").read_text(
                    encoding="utf-8"
                )
            )
            for relative in policy["allowed_product_go_files"]:
                shutil.copy2(ROOT / relative, root / relative)
            shutil.copy2(ROOT / "go.mod", root / "go.mod")
            (root / "policy").mkdir()
            shutil.copy2(
                ROOT / "policy" / "phase1-readonly.json",
                root / "policy" / "phase1-readonly.json",
            )
            endpoint = root / "rtu_endpoint.go"
            endpoint.write_text(
                endpoint.read_text(encoding="utf-8")
                + "\nfunc physicalEscape(dst io.Writer) {}\n",
                encoding="utf-8",
            )
            with self.assertRaises(validator.AcceptanceError):
                validator.validate_offline_surface(
                    root,
                    {
                        "physical_io_sites": 0,
                        "gateway_dependencies": 0,
                        "vendor_profile_dependencies": 0,
                        "cgo_files": 0,
                        "go_mod_sha256": (
                            "c64fd63d81e8a9c6b013d06f8db676621b3945be57e203b"
                            "d004910270383617f"
                        ),
                    },
                )

    def test_hosted_red_requires_both_jobs_and_missing_runtime(self) -> None:
        red = "f5e55fccafc060c5556d5510ddb373dc8dbc2bf4"
        payload = {
            "conclusion": "failure",
            "event": "pull_request",
            "headSha": red,
            "workflowName": "CI",
            "jobs": [
                {"name": "checks", "conclusion": "failure"},
                {"name": "lint", "conclusion": "failure"},
            ],
        }
        log = "\n".join(
            (
                "undefined: RTUEvent",
                "undefined: RTUFixtureEndpoint",
                "undefined: RTUReadPlan",
                "undefined: RTUTiming",
                "undefined: EncodeRTUReadADU",
                "undefined: DecodeRTUReadResponseADU",
            )
        )
        validator.validate_tdd_hosted_payload(red, payload, log)
        with self.assertRaises(validator.AcceptanceError):
            validator.validate_tdd_hosted_payload(
                red,
                payload,
                log.replace("undefined: RTUTiming", ""),
            )

    def test_hosted_red_is_bound_to_exact_run_pr_and_base(self) -> None:
        red = "f5e55fccafc060c5556d5510ddb373dc8dbc2bf4"
        run = {
            "id": 30367710672,
            "event": "pull_request",
            "head_sha": red,
            "head_branch": "issue/9-fixture-only-modbus-rtu",
            "path": ".github/workflows/ci.yml",
            "run_attempt": 1,
            "conclusion": "failure",
        }
        pulls = [
            {
                "number": 10,
                "state": "open",
                "base_ref": "main",
                "base_sha": (
                    "79f9c6da6efd5be9f3e31ddf62720c1a3d0bf3e7"
                ),
                "head_sha": "b04fa221ff638b5cbb4bdcb8b08f5919643524fc",
            }
        ]
        validator.validate_tdd_hosted_binding(red, run, pulls)
        pulls[0]["state"] = "closed"
        validator.validate_tdd_hosted_binding(red, run, pulls)
        pulls[0]["base_sha"] = "0" * 40
        with self.assertRaises(validator.AcceptanceError):
            validator.validate_tdd_hosted_binding(red, run, pulls)

    def test_compiled_inventory_rejects_extra_test_and_non_go_sources(
        self,
    ) -> None:
        policy = json.loads(
            (ROOT / "policy" / "phase1-readonly.json").read_text(
                encoding="utf-8"
            )
        )
        package = {
            "GoFiles": policy["allowed_product_go_files"],
            "TestGoFiles": sorted(validator.EXPECTED_TEST_GO_FILES),
        }
        validator.validate_compiled_inventory(package, policy)
        package["TestGoFiles"].append("m1_03_extra_test.go")
        with self.assertRaises(validator.AcceptanceError):
            validator.validate_compiled_inventory(package, policy)
        package["TestGoFiles"].pop()
        package["SFiles"] = ["unlocked_amd64.s"]
        with self.assertRaises(validator.AcceptanceError):
            validator.validate_compiled_inventory(package, policy)

    def test_offline_filesystem_rejects_arch_specific_and_embed_sources(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "unlocked_amd64.s").write_text("TEXT", encoding="utf-8")
            with self.assertRaises(validator.AcceptanceError):
                validator.validate_offline_source_filesystem(root)
            (root / "unlocked_amd64.s").unlink()
            (root / "ignored_arm64_test.go").write_text(
                "package modbus\n//go:embed hidden.bin\n",
                encoding="utf-8",
            )
            with self.assertRaises(validator.AcceptanceError):
                validator.validate_offline_source_filesystem(root)

    def test_ci_publication_mode_controls_are_hash_locked(self) -> None:
        validator.validate_ci_mode_controls(ROOT)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            workflow = root / ".github/workflows/ci.yml"
            workflow.parent.mkdir(parents=True)
            shutil.copy2(ROOT / ".github/workflows/ci.yml", workflow)
            script = root / "scripts/ci_local.sh"
            script.parent.mkdir(parents=True)
            script.write_text(
                (ROOT / "scripts/ci_local.sh").read_text(encoding="utf-8")
                .replace(
                    "python3 scripts/validate_m1_03_acceptance.py",
                    "python3 scripts/validate_m1_03_acceptance.py --candidate",
                ),
                encoding="utf-8",
            )
            with self.assertRaises(validator.AcceptanceError):
                validator.validate_ci_mode_controls(root)

    def test_requirement_source_identity_is_immutable(self) -> None:
        document = json.loads(
            (ROOT / "policy" / "m1-03-acceptance.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertTrue(validator.validate_requirement_contract(document))
        document["requirements"][0]["source"] = "self-authored#replacement"
        with self.assertRaises(validator.AcceptanceError):
            validator.validate_requirement_contract(document)

    def test_requirement_mapping_cannot_collapse_to_one_test(self) -> None:
        document = json.loads(
            (ROOT / "policy" / "m1-03-acceptance.json").read_text(
                encoding="utf-8"
            )
        )
        for requirement in document["requirements"]:
            requirement["tests"] = ["TestContract"]
        with self.assertRaises(validator.AcceptanceError):
            validator.validate_requirement_contract(document)

    def test_merge_topology_requires_one_parent_equal_to_base(self) -> None:
        merge = "a" * 40
        base = "b" * 40
        validator.validate_squash_topology(
            merge,
            base,
            f"{merge} {base}\n",
        )
        with self.assertRaises(validator.AcceptanceError):
            validator.validate_squash_topology(
                merge,
                base,
                f"{merge} {base} {'c' * 40}\n",
            )


if __name__ == "__main__":
    unittest.main()
