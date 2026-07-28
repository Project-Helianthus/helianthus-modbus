from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "validate_m1_02_acceptance.py"
SPEC = importlib.util.spec_from_file_location("validate_m1_02_acceptance", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)


def event(action: str, test: str) -> str:
    return json.dumps({"Action": action, "Test": test})


class M102AcceptanceTests(unittest.TestCase):
    def reviewed_revision_fixture(
        self,
    ) -> tuple[dict[str, object], dict[str, object]]:
        evidence = {
            "repository": "Project-Helianthus/helianthus-modbus",
            "pull_request": 6,
            "reviewed_head_sha": (
                "0aac61ddad62f664b47900334c48803587183fa3"
            ),
            "reviewed_head_tree_sha": (
                "ac81a5294a84a1783cb84f56cfe1ba455291c1ee"
            ),
            "squash_merge_sha": (
                "467229104bfe34ca90aa653ca22ad79da4fa9a32"
            ),
            "squash_merge_tree_sha": (
                "ac81a5294a84a1783cb84f56cfe1ba455291c1ee"
            ),
        }
        pull_request = {
            "number": 6,
            "state": "MERGED",
            "baseRefName": "main",
            "headRefOid": evidence["reviewed_head_sha"],
            "mergeCommit": {"oid": evidence["squash_merge_sha"]},
            "mergedAt": "2026-07-28T13:41:17Z",
        }
        return evidence, pull_request

    def test_squash_merge_preserves_reviewed_tdd_chain(self) -> None:
        evidence, pull_request = self.reviewed_revision_fixture()
        validator.validate_reviewed_revision_payload(
            evidence,
            pull_request,
            red_is_ancestor_of_reviewed_head=True,
            reviewed_head_tree=str(evidence["reviewed_head_tree_sha"]),
            squash_merge_tree=str(evidence["squash_merge_tree_sha"]),
            squash_merge_is_ancestor_of_head=True,
        )

    def test_squash_merge_rejects_stale_reviewed_head(self) -> None:
        evidence, pull_request = self.reviewed_revision_fixture()
        pull_request["headRefOid"] = "1" * 40
        with self.assertRaises(validator.AcceptanceError):
            validator.validate_reviewed_revision_payload(
                evidence,
                pull_request,
                red_is_ancestor_of_reviewed_head=True,
                reviewed_head_tree=str(evidence["reviewed_head_tree_sha"]),
                squash_merge_tree=str(evidence["squash_merge_tree_sha"]),
                squash_merge_is_ancestor_of_head=True,
            )

    def test_squash_merge_rejects_tree_mismatch(self) -> None:
        evidence, pull_request = self.reviewed_revision_fixture()
        with self.assertRaises(validator.AcceptanceError):
            validator.validate_reviewed_revision_payload(
                evidence,
                pull_request,
                red_is_ancestor_of_reviewed_head=True,
                reviewed_head_tree=str(evidence["reviewed_head_tree_sha"]),
                squash_merge_tree="2" * 40,
                squash_merge_is_ancestor_of_head=True,
            )

    def test_squash_merge_rejects_wrong_merge_sha(self) -> None:
        evidence, pull_request = self.reviewed_revision_fixture()
        pull_request["mergeCommit"] = {"oid": "3" * 40}
        with self.assertRaises(validator.AcceptanceError):
            validator.validate_reviewed_revision_payload(
                evidence,
                pull_request,
                red_is_ancestor_of_reviewed_head=True,
                reviewed_head_tree=str(evidence["reviewed_head_tree_sha"]),
                squash_merge_tree=str(evidence["squash_merge_tree_sha"]),
                squash_merge_is_ancestor_of_head=True,
            )

    def test_squash_merge_must_retain_red_ancestry_on_reviewed_head(self) -> None:
        evidence, pull_request = self.reviewed_revision_fixture()
        with self.assertRaises(validator.AcceptanceError):
            validator.validate_reviewed_revision_payload(
                evidence,
                pull_request,
                red_is_ancestor_of_reviewed_head=False,
                reviewed_head_tree=str(evidence["reviewed_head_tree_sha"]),
                squash_merge_tree=str(evidence["squash_merge_tree_sha"]),
                squash_merge_is_ancestor_of_head=True,
            )

    def test_squash_merge_must_be_ancestor_of_current_head(self) -> None:
        evidence, pull_request = self.reviewed_revision_fixture()
        with self.assertRaises(validator.AcceptanceError):
            validator.validate_reviewed_revision_payload(
                evidence,
                pull_request,
                red_is_ancestor_of_reviewed_head=True,
                reviewed_head_tree=str(evidence["reviewed_head_tree_sha"]),
                squash_merge_tree=str(evidence["squash_merge_tree_sha"]),
                squash_merge_is_ancestor_of_head=False,
            )

    def test_skipped_required_subtest_is_rejected(self) -> None:
        output = "\n".join(
            (
                event("run", "TestContract"),
                event("run", "TestContract/behavior"),
                event("skip", "TestContract/behavior"),
                event("pass", "TestContract"),
            )
        )
        with self.assertRaises(validator.AcceptanceError):
            validator.evaluate_mapped_test_events(
                {"TestContract"},
                output,
                "",
                0,
            )

    def test_passing_required_subtest_is_accepted(self) -> None:
        output = "\n".join(
            (
                event("run", "TestContract"),
                event("run", "TestContract/behavior"),
                event("pass", "TestContract/behavior"),
                event("pass", "TestContract"),
            )
        )
        validator.evaluate_mapped_test_events(
            {"TestContract"},
            output,
            "",
            0,
        )

    def test_requirement_identity_is_anchored_to_canonical_sources(self) -> None:
        document = {
            "requirements": [
                {"id": requirement, "source": source, "tests": ["TestContract"]}
                for requirement, source in validator.EXPECTED_REQUIREMENTS
            ]
        }
        self.assertEqual(
            validator.validate_requirement_contract(document),
            {"TestContract"},
        )
        document["requirements"][0]["source"] = "self-authored#replacement"
        with self.assertRaises(validator.AcceptanceError):
            validator.validate_requirement_contract(document)

    def test_canonical_plan_bytes_are_content_anchored(self) -> None:
        plan = validator.read_git_blob(
            validator.PLAN_SOURCE["repository"],
            validator.PLAN_SOURCE["commit_sha"],
            validator.PLAN_SOURCE["path"],
        )
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            lock_path = root / validator.COMPANION_SOURCE["consumer_lock_path"]
            lock_path.parent.mkdir(parents=True)
            lock_path.write_text(
                json.dumps(
                    {
                        "repository": validator.COMPANION_SOURCE["repository"],
                        "merged_commit_sha": (
                            validator.COMPANION_SOURCE["commit_sha"]
                        ),
                        "manifest_sha256": (
                            validator.COMPANION_SOURCE["manifest_sha256"]
                        ),
                    }
                ),
                encoding="utf-8",
            )
            document = {
                "canonical_sources": {
                    "companion_contract": validator.COMPANION_SOURCE,
                    "execution_plan": validator.PLAN_SOURCE,
                }
            }
            validator.validate_canonical_sources(root, document, plan)
            with self.assertRaises(validator.AcceptanceError):
                validator.validate_canonical_sources(
                    root,
                    document,
                    plan + b"\n# mutation\n",
                )

    def test_transport_matrix_requires_every_canonical_tcp_row(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            relative = Path("policy/m1-02-transport-matrix.json")
            target = root / relative
            target.parent.mkdir(parents=True)
            target.write_bytes((ROOT / relative).read_bytes())
            document = {
                "gates": {
                    "transport_gate": {
                        "matrix_path": relative.as_posix(),
                        "matrix_sha256": validator.sha256(target.read_bytes()),
                    }
                }
            }
            tests = validator.validate_transport_matrix(root, document)
            self.assertTrue(tests)
            matrix = json.loads(target.read_text(encoding="utf-8"))
            matrix["rows"].pop()
            target.write_text(json.dumps(matrix), encoding="utf-8")
            document["gates"]["transport_gate"]["matrix_sha256"] = (
                validator.sha256(target.read_bytes())
            )
            with self.assertRaises(validator.AcceptanceError):
                validator.validate_transport_matrix(root, document)

    def test_pending_tdd_red_evidence_is_rejected(self) -> None:
        with self.assertRaises(validator.AcceptanceError):
            validator.validate_tdd_red(
                ROOT,
                {
                    "commit_sha": "037264cbfdea82fb73c64978fa538c34855cf48b",
                    "required_shape": "tests_only_parented_by_fmv3_m1_01",
                    "hosted_ci_conclusion": "failure",
                    "hosted_ci_run_url": None,
                },
                set(),
                verify_hosted=False,
            )

    def test_hosted_tdd_red_uses_numeric_run_id(self) -> None:
        run_id = validator.github_run_id(
            "https://github.com/Project-Helianthus/"
            "helianthus-modbus/actions/runs/30353538725"
        )
        self.assertEqual(run_id, "30353538725")
        with self.assertRaises(validator.AcceptanceError):
            validator.github_run_id(
                "https://github.com/Project-Helianthus/"
                "helianthus-modbus/actions/runs/not-a-run"
            )

    def test_hosted_tdd_red_requires_missing_runtime_failure(self) -> None:
        commit = "037264cbfdea82fb73c64978fa538c34855cf48b"
        hosted = {
            "conclusion": "failure",
            "event": "pull_request",
            "headSha": commit,
            "workflowName": "CI",
            "jobs": [
                {
                    "name": "lint",
                    "conclusion": "failure",
                    "databaseId": 1,
                }
            ],
        }
        log = "\n".join(
            (
                "undefined: TCPEndpoint",
                "undefined: TCPTransportEvent",
                "undefined: ReadIntent",
                "undefined: EndpointScheduler",
            )
        )
        validator.validate_tdd_hosted_payload(commit, hosted, log)
        with self.assertRaises(validator.AcceptanceError):
            validator.validate_tdd_hosted_payload(
                commit,
                hosted,
                "runner unavailable",
            )

    def test_doc_gate_requires_exact_successful_job_and_log(self) -> None:
        run_id, job_id = validator.docs_run_and_job_ids(
            "https://github.com/Project-Helianthus/"
            "helianthus-docs-ebus/actions/runs/30238777804/"
            "job/89891563104"
        )
        self.assertEqual(run_id, "30238777804")
        hosted = {
            "conclusion": "success",
            "event": "pull_request_target",
            "workflowName": "Modbus Trusted Revision",
            "jobs": [
                {
                    "name": "Modbus Trusted Revision",
                    "conclusion": "success",
                    "databaseId": int(job_id),
                }
            ],
        }
        log = "\n".join(
            (
                validator.COMPANION_SOURCE["commit_sha"],
                validator.PLAN_SOURCE["commit_sha"],
                "modbus_docs_trust_ok",
            )
        )
        validator.validate_doc_hosted_payload(job_id, hosted, log)
        with self.assertRaises(validator.AcceptanceError):
            validator.docs_run_and_job_ids(
                "https://github.com/Project-Helianthus/"
                "helianthus-docs-ebus/actions/runs/1"
            )
        with self.assertRaises(validator.AcceptanceError):
            validator.validate_doc_hosted_payload(
                job_id,
                hosted,
                "modbus_docs_trust_ok",
            )


if __name__ == "__main__":
    unittest.main()
