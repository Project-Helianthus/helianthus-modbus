// Command acceptance_evidence emits a JSON inventory of repository test names
// and computed source fingerprints for acceptance-map validation. It takes one
// repository-root argument and parses test source without executing tests.
// Fingerprints identify the inspected source; they do not establish test success,
// device compatibility, or hardware qualification. Invalid input exits nonzero.
package main
