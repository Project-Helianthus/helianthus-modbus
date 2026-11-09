// Command read_only_surface checks the repository's vendor-neutral read-only
// API and transport ownership boundaries by inspecting Go syntax. It takes one
// repository-root argument, reads source without opening devices or connections,
// and exits nonzero when the enforced surface is violated. Private-function
// byte framing is checked as transport infrastructure, not operation admission.
package main
