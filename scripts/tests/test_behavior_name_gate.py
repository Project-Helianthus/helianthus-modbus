"""Synthetic public tests for exact behavior-name debt and protocol vocabulary."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    "behavior_guard", Path(__file__).resolve().parents[1] / "check_behavior_names.py")
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


class BehaviorNameGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.policy = self.root / "policy.json"
        self.data = json.loads(GATE.BASELINE.read_text())
        self.data["baseline"] = []
        self.save()

    def save(self):
        self.policy.write_text(json.dumps(self.data))

    def source(self, text, name="read.go"):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def check(self):
        return GATE.check(self.root, self.policy)

    def test_protocol_and_domain_names(self):
        self.source("""package modbus
func TestFC03Read() {}
func TestFC04Read() {}
func TestFC2BMEI0ERead() {}
type TCPRTU struct { Uint16 int }; type CRC16 struct{}
func TestRTUFC03Read() {}
func Read(ctx2 int) {}
""")
        self.assertEqual(self.check(), [])

    def test_payloads_comments_and_uses_are_not_declarations(self):
        self.source('''package modbus
// XY73 and Batch73 are prose.
func Read() { println("XY73", "Batch73"); remote.XY73() }
''')
        self.assertEqual(self.check(), [])

    def test_all_declaration_kinds_and_test_names(self):
        self.source("""package XY73
import XY74 "fmt"
type XY75 struct { XY76 int }
var XY77, XY78 int
func (receiver *XY75) XY79(XY80 int) (XY81 int) {
 localXY82 := 0
 for XY83 := range []int{} { _ = XY83 }
XY84: for { break XY84 }
 return
}
func TestXY85Read() {}
func BenchmarkXY86Read() {}
func FuzzXY87Read() {}
func ExampleXY88Read() {}
type XY89 interface { XY90(XY91 int) }
func Generic[XY92 any]() {}
""")
        found = self.check()
        symbols = {entry[1] for entry in found}
        for number in range(73, 93):
            with self.subTest(number=number):
                self.assertTrue(any("XY" + str(number) in s for s in symbols))
        self.assertIn(("read.go", "TestXY85Read", "test"), found)

    def test_delivery_forms_and_new_files(self):
        for name in ["TestBatch73Read", "TestWave73Read", "TestIssue73Read",
                     "TestTicket73Read", "TestXY73Read", "xy73_read.go",
                     "batch_73_read.go", "wave-73-read.go", "issue73_read.go"]:
            with self.subTest(name=name):
                entry = {"path": name, "symbol": name, "category": "filename"}
                self.assertTrue(GATE.violations([entry], set()))
        self.source("package modbus", "xy73_read.go")
        self.assertIn(("xy73_read.go", "xy73_read.go", "filename"), self.check())
        self.source("package modbus; func TestXY74Read() {}", "new/read_test.go")
        self.assertIn(("new/read_test.go", "TestXY74Read", "test"), self.check())

    def test_exact_baseline_and_reductions(self):
        self.source("package modbus; func TestXY73Read() {}")
        self.data["baseline"] = [{"path": "read.go", "symbol": "TestXY73Read", "category": "test"}]
        self.save()
        self.assertEqual(self.check(), [])
        self.source("package modbus; func TestRead() {}")
        self.assertEqual(self.check(), [])

    def test_each_baseline_identity_field_is_enforced(self):
        # Each field independently changes, catching dropped path/symbol/category
        # comparisons rather than merely checking one renamed fixture.
        original = {"path": "read.go", "symbol": "TestXY73Read", "category": "test"}
        self.source("package modbus; func TestXY73Read() {}")
        for field, changed in [("path", "other.go"), ("symbol", "TestXY74Read"),
                               ("category", "identifier")]:
            with self.subTest(field=field):
                entry = dict(original, **{field: changed})
                self.data["baseline"] = [entry]
                self.save()
                self.assertIn(tuple(original[k] for k in ("path", "symbol", "category")), self.check())

    def test_rename_move_and_same_file_addition_cannot_bypass(self):
        self.data["baseline"] = [{"path": "read.go", "symbol": "TestXY73Read", "category": "test"}]
        self.save()
        path = self.source("package modbus; func TestXY73Read() {}")
        path.rename(self.root / "moved.go")
        self.assertTrue(self.check())
        (self.root / "moved.go").unlink()
        self.source("package modbus; func TestXY74Read() {}; func TestXY73Read() {}")
        self.assertEqual(self.check(), [("read.go", "TestXY74Read", "test")])

    def test_exception_fields_are_exact_and_reasoned(self):
        vocabulary, _ = GATE.load_policy(self.policy)
        entries = [{"path": "read.go", "symbol": name, "category": "identifier"}
                   for name in ["FC03Read", "FC030Read", "FC05Read"]]
        self.assertEqual([x[1] for x in GATE.violations(entries, vocabulary)],
                         ["FC030Read", "FC05Read"])
        for field, value in [("token", "FC.*"), ("reason", " ")]:
            with self.subTest(field=field):
                self.data["exceptions"] = [{"token": "FC03", "reason": "Public contract", field: value}]
                self.save()
                with self.assertRaises(ValueError):
                    GATE.load_policy(self.policy)

    def test_stable_external_or_conformance_vocabulary_is_explicit(self):
        self.source("package modbus; func CaseCX73() {}")
        self.assertTrue(self.check())
        self.data["exceptions"].append({"token": "CX73", "reason": "Synthetic stable conformance contract case."})
        self.save()
        self.assertEqual(self.check(), [])
        self.source("package modbus; func CaseCX74() {}")
        self.assertTrue(self.check())

    def test_no_wildcard_baseline(self):
        self.data["baseline"] = [{"path": "*.go", "symbol": "XY73", "category": "identifier"}]
        self.save()
        with self.assertRaises(ValueError):
            GATE.load_policy(self.policy)

    def test_platform_and_build_excluded_sources_are_checked(self):
        self.source("//go:build synthetic_platform\n\npackage modbus; var XY73 int", "read_otheros.go")
        self.assertTrue(self.check())

    def test_invalid_go_fails_closed(self):
        self.source("package modbus; func (")
        with self.assertRaises(Exception):
            self.check()


if __name__ == "__main__":
    unittest.main()
