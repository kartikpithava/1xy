# AI Generation Checklist v2 - Production-Grade Rust Code Quality

This checklist is to be used **before, during, and after AI-generated module implementation**, and is designed to prevent compilation errors, type mismatches, placeholder logic, outdated APIs, and integration failures.

---

## 1. Type Registry Check

### Before Implementation:
- [ ] Review all existing types in `types.rs` 
- [ ] Check for existing enums that match your needs (e.g., `ValidationSeverity`, `SecurityAction`)
- [ ] Document any new types that will be needed
- [ ] Plan import hierarchy - ensure no circular dependencies
- [ ] Verify no duplicate type names will be created across modules

### During Implementation:
- [ ] Import existing types from `types.rs` using qualified imports
- [ ] Never redefine types that already exist elsewhere
- [ ] Add new types to `types.rs` if they will be shared across modules
- [ ] Use existing error types (`PdfError`, `SecurityLevel`) consistently

### After Implementation:
- [ ] Verify all types are properly imported and no duplicates exist
- [ ] Check that new types follow project naming conventions
- [ ] Ensure proper visibility modifiers (`pub`, `pub(crate)`, private)

---

## 2. Dependency & Crate Validation

### Cargo.toml Verification:
- [ ] Check existing crate versions in `Cargo.toml` before adding new dependencies
- [ ] Never use wildcard (`*`) versions in production code
- [ ] Use exact version pinning for critical security/cryptographic crates
- [ ] Validate all required crate features are enabled (e.g., `serde/derive`, `tokio/full`, `uuid/v4`)
- [ ] Match function/method usage to the actual crate version (check docs.rs)
- [ ] Do not assume default crate behavior — verify actual exports

### Feature Validation:
- [ ] Ensure required features are enabled for: `serde`, `chrono`, `uuid`, `tokio`, `ring`
- [ ] Verify async runtime compatibility (tokio vs async-std)
- [ ] Check cryptographic crate features for security modules
- [ ] Validate serialization features for data persistence

### Version Compatibility:
- [ ] Test that new dependencies don't conflict with existing ones
- [ ] Verify API compatibility with planned usage patterns
- [ ] Check for breaking changes in minor version updates

---

## 3. Function Signature and API Matching

### Function Definitions:
- [ ] All function calls must match existing definitions exactly
- [ ] Never invent functions that don't exist in crates or project
- [ ] Validate argument count, types, and order
- [ ] Match return types exactly (`Result<T, PdfError>` vs `Result<T, Error>`)
- [ ] Use project-specific result types consistently

### Method Validation:
- [ ] Avoid using outdated methods (e.g., old `digest()` APIs)
- [ ] Verify async/await compatibility for all async functions
- [ ] Check trait method requirements and implementations
- [ ] Ensure proper error propagation using `?` operator

### API Consistency:
- [ ] Follow existing patterns for similar functionality
- [ ] Use consistent parameter naming across modules
- [ ] Maintain consistent error handling approaches
- [ ] Follow project conventions for async vs sync functions

---

## 4. Trait Bounds and Derives

### Required Derives:
- [ ] Add `Debug` derive for all public types
- [ ] Add `Clone` derive when types need to be cloned
- [ ] Add `Serialize, Deserialize` for types that need persistence
- [ ] Add `PartialEq, Eq` for types used in comparisons or as HashMap keys
- [ ] Add `Hash` for types used as HashMap/HashSet keys

### Async Compatibility:
- [ ] Ensure types passed to async/parallel APIs implement `Send + Sync + 'static`
- [ ] Verify thread safety for types used across async boundaries
- [ ] Check lifetime requirements for async function parameters

### Trait Implementation Validation:
- [ ] Don't call `.clone()` unless `Clone` is derived/implemented
- [ ] Don't call `.default()` unless `Default` is implemented
- [ ] Don't use `serde_json::to_string()` unless `Serialize` is derived
- [ ] Verify all trait bounds are satisfied before usage

---

## 5. Implementation Hygiene

### No Placeholder Logic:
- [ ] Never use `todo!()`, `unimplemented!()`, or `unreachable!()` in production code
- [ ] No `Default::default()` with fake/meaningless values
- [ ] All functions must have complete, meaningful implementations
- [ ] No empty error handlers or catch-all arms

### Real Business Logic:
- [ ] Implement actual algorithms, not stubs or pass-throughs
- [ ] Use proper error handling with meaningful error messages
- [ ] Implement real validation logic, not always-true/false returns
- [ ] Provide concrete implementations for all abstract concepts

### Code Quality:
- [ ] Remove unused parameters, variables, and imports
- [ ] Use meaningful variable and function names
- [ ] Add proper documentation for public functions and types
- [ ] Follow consistent coding style and formatting

---

## 6. Import Management

### Import Organization:
- [ ] Use qualified imports: `use crate::types::HashResult`
- [ ] Avoid wildcard imports: never use `use module::*`
- [ ] Group imports in order: std → external crates → local crate modules
- [ ] Sort imports alphabetically within each group

### Import Validation:
- [ ] Verify all imports are actually used
- [ ] Check for circular import dependencies
- [ ] Use appropriate visibility for re-exports
- [ ] Prefer specific imports over broad module imports

### Module Structure:
- [ ] Import from appropriate abstraction levels
- [ ] Don't import from higher-level modules into lower-level ones
- [ ] Use `pub use` for convenient re-exports when appropriate

---

## 7. Module Structure Rules

### Module Registration:
- [ ] All new modules must be registered in `mod.rs` or `lib.rs`
- [ ] Use proper module hierarchy (no orphaned modules)
- [ ] Follow consistent module naming conventions
- [ ] Organize modules by functionality, not by type

### Dependency Hierarchy:
- [ ] Lower-level modules should not import from higher-level modules
- [ ] Shared types should be in `types.rs` or common modules
- [ ] Avoid circular dependencies between modules
- [ ] Use dependency injection patterns for complex dependencies

### Visibility Management:
- [ ] Use `pub(crate)` for internal APIs
- [ ] Use `pub` only for truly public interfaces
- [ ] Keep implementation details private
- [ ] Document public API contracts clearly

---

## 8. Security Module Specific Rules

### Cryptographic Implementation:
- [ ] Use established cryptographic libraries (`ring`, `rustls`, etc.)
- [ ] Never implement custom cryptographic algorithms
- [ ] Properly handle cryptographic keys and secrets
- [ ] Use secure random number generation

### Error Handling:
- [ ] Never expose sensitive information in error messages
- [ ] Use appropriate error types for security contexts
- [ ] Implement proper error propagation chains
- [ ] Log security events appropriately without exposing secrets

### Thread Safety:
- [ ] Ensure security-critical types are thread-safe when needed
- [ ] Use appropriate synchronization primitives
- [ ] Verify async safety for security operations
- [ ] Handle concurrent access to security state properly

---

## 9. Integration and Testing

### Integration Points:
- [ ] Verify integration with existing error handling system
- [ ] Test interaction with other security modules
- [ ] Validate performance under realistic loads
- [ ] Check memory usage and resource cleanup

### Test Coverage:
- [ ] Test all public API functions
- [ ] Test error conditions and edge cases
- [ ] Validate security properties and invariants
- [ ] Test async behavior and cancellation

### Validation Steps:
- [ ] Run `python project_validator.py .` to detect issues
- [ ] Run `cargo check` for compilation validation
- [ ] Run `cargo test` for functional verification
- [ ] Run `cargo clippy` for additional code quality checks

---

## 10. Red Flag Conditions (AI Must Never Do These)

### ❌ Type System Violations:
- Creating a struct or enum already defined in another file
- Using types that don't exist or are incorrectly imported
- Mismatching generic parameters or lifetimes
- Creating circular type dependencies

### ❌ API Misuse:
- Calling functions or methods that don't exist
- Using incorrect function signatures or parameter types
- Assuming API behavior without verification
- Using deprecated or removed APIs

### ❌ Placeholder Code:
- Using `todo!()`, `unimplemented!()`, or similar macros
- Implementing `Default::default()` with meaningless values
- Creating empty error handlers or always-success functions
- Using hardcoded values instead of proper logic

### ❌ Security Violations:
- Hardcoding secrets or sensitive data
- Using weak or deprecated cryptographic algorithms
- Exposing sensitive information in logs or errors
- Implementing custom security algorithms

### ❌ Build System Issues:
- Adding dependencies without proper feature flags
- Using incompatible crate versions
- Missing required derive macros for functionality
- Creating modules without proper registration

---

## 11. Post-Implementation Verification

### Final Checklist:
- [ ] All code compiles without warnings
- [ ] All tests pass successfully
- [ ] No placeholder or stub implementations remain
- [ ] Security review completed for security-related modules
- [ ] Documentation is complete and accurate
- [ ] Performance meets requirements
- [ ] Memory usage is within acceptable limits
- [ ] Integration with existing codebase is seamless

### Quality Gates:
- [ ] Code review by senior developer (if applicable)
- [ ] Security audit for security-critical code
- [ ] Performance benchmarking for performance-critical code
- [ ] Integration testing with dependent modules
- [ ] Regression testing to ensure no existing functionality is broken

---

This checklist should be referenced throughout the AI code generation process to ensure production-quality, maintainable, and secure Rust code that integrates seamlessly with existing systems.