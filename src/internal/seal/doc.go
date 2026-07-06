// Package seal implements the Shamir seal and defines the auto-unseal
// interface (transit/KMS implementations land in Phase 8). Unsealing
// reconstructs the root key that protects the barrier key. Implemented in
// Phase 1.
package seal
