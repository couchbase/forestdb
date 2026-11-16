# AGENTS.md — ForestDB Repository Guide

Repository (mirror): https://github.com/couchbase/forestdb

Primary code review system: https://review.couchbase.org

---

## 📌 Purpose

This document defines expectations for:

- Automated coding agents
- Human contributors
- Reviewers

ForestDB uses Gerrit (review.couchbase.org) for all change submission,
validation, and approval.

GitHub is a mirror only. Do NOT open GitHub Pull Requests.

---

## 🧱 Repository Overview

Welcome to the Couchbase _ForestDB_ project.

ForestDB is a key-value storage engine whose main index structure is
the HB+-Trie (Hierarchical B+-Tree based Trie). The committed README.md
provides a high-level overview of the project and its features, and
INSTALL.md describes dependencies and standalone builds:

@README.md

Layout:

- `include/libforestdb/` — public C API (`forestdb.h`, `fdb_types.h`,
  `fdb_errors.h`)
- `src/` — engine implementation (file manager, block cache, WAL,
  HB+-Trie, B-tree, compactor, background flusher, ...)
- `utils/` — shared helpers (CRC, hashing, timing, ...)
- `tools/` — command line utilities (`forestdb_dump`,
  `forestdb_hexamine`)
- `tests/` — unit, functional, e2e, anomaly, use case, and micro
  benchmark tests

## 🚦 Authoritative Contribution Workflow

All changes must be submitted via:

    https://review.couchbase.org

### Standard Flow

1. Sync with latest target branch (typically `master`)
2. Create a local topic branch (if `repo` is available):

       `repo start name-of-topic-branch`

3. Make code changes and run `git clang-format` to fix any formatting
   errors before committing. Verify that the changes don't introduce any
   new `clang-tidy` warnings.
4. Make atomic, focused commits
5. Always create suitable unit tests
6. Run local build and tests
7. Sync with upstream and rebase the change. If `repo` is available:

       repo sync .
       repo rebase .

8. Push to Gerrit (substitute master for correct branch when working on
   named branches):

       git push gerrit HEAD:refs/for/master

   Alternatively, if the `repo` tool is available:

       repo upload --cbr .

9. CI validation runs automatically on jenkins servers that are
   monitoring for new code pushed to gerrit.
10. Review feedback is asynchronous

---

## 📐 Code Standards

Language: **C++ (up to C++23 supported)**

ForestDB started out as a C-style code base and large parts of it still
look that way (raw pointers, `malloc`/`free`, C-style arrays, `/* */`
comments). The public API in `include/libforestdb/` is a C API and must
remain usable from C.

Guidelines:

- Prefer modern C++ where appropriate (C++23 features are supported)
- Use RAII, smart pointers, and standard library facilities where they
  improve safety and clarity
- Structured bindings, `std::optional`, `std::variant`, `constexpr`, and
  other modern features are acceptable
- Prefer `std::expected` over a `std::variant<T, Error>` (or similar
  ad-hoc encoding) when a function can fail with an informative error.
  `std::expected` is the idiomatic, standard-library way to express
  "value or error" in modern C++ (C++23) — it makes the success/failure
  contract explicit in the return type, avoids the boilerplate of
  visiting a variant to distinguish the value case from the error case,
  and composes naturally with `and_then`/`or_else`/`transform`. Only
  fall back to `fdb_status` return codes, exceptions, or `std::optional`
  where the surrounding code's existing error-handling style makes that
  the better fit. Exceptions must never propagate out through the public
  C API.
- Use designated initializers introduced in C++20
- Don't use C-style arrays in new code, use `std::array` or
  `std::vector` instead
- Don't use single character variable names
- Always use braces for control structures, even if they are optional
- Match the surrounding style within the modified module.
- It is acceptable to use older constructs if required for consistency
  with the existing code in that area
- Avoid unnecessary large-scale modernization in unrelated code
- Run `git clang-format` to format changed lines and fix any formatting
  errors before committing
- Maintain cross-platform compatibility (Linux, macOS, Windows)
- New source files must use the current year in the banner comment.
- The
  `C++ Core Guidelines<http://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines>`
  are also a key part of our coding style.
- Always build (see building hints) before running tests!
- Use Doxygen style for all new code comments, using `/** ... */` block
  comment style exclusively (not `///` or `/*!`). The first sentence of
  the comment acts as the brief description (do not use the `@brief` tag
  explicitly). Use tags such as `@param`, `@return`, and `@throws`.

Language: **CMake**

Guidelines:

- Use modern CMake style (target-based, avoid global properties)
- Prefer `target_include_directories` and `target_link_libraries` for
  dependencies
- Follow existing patterns in the repository for consistency
- Avoid global variables and side effects in CMake scripts
- The `CMake Best Practices<https://cliutils.gitlab.io/modern-cmake/>`
  are also a key part of our CMake style.

## New C++ File Headers

Whenever you create a new C++ file (e.g., `.cc`, or `.h`), you must
prepend the exact copyright header specified below. ForestDB is licensed
under the Apache License, Version 2.0 (see `LICENSE`).

### Execution Rules
1. **Dynamic Year**: Automatically replace [YEAR] with the current year
   (e.g. 2026).
2. **Existing Files**: Do not modify or duplicate the header if editing
   an existing file.

### C++ Header Template

```cpp
/*
 *     Copyright [YEAR]-Present Couchbase, Inc.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */
```

---

## Building hints

The project uses CMake for build configuration.

- The build directory is `build/` in the parent directory of the
  `forestdb` git repository (`../build` relative to the root of the
  repository).
- To build all code (including all tests) use the target
  `forestdb_everything`, which can be invoked from the build directory:

      ninja -C ../build forestdb_everything

- Prefer to reuse the existing build directory and do incremental
  builds.
  - Do not create a new build directory unless asked.
- Prefer `ninja` when building.
- If configuring a new build, prefer using the script ../Build.sh
  (should be executed in the parent directory)

## Running tests

The tests use a small home-grown framework (`tests/include/test.h`,
with macros such as `TEST_INIT`, `TEST_CHK`, `TEST_STATUS` and
`TEST_RESULT`), not GoogleTest. Each test program is registered with
CTest:

    cd ../build/forestdb && ctest --output-on-failure
    cd ../build/forestdb && ctest -R filemgr_test --output-on-failure

Several tests create data files in their working directory; run them via
`ctest` (or from within their build output directory) rather than from
the source tree.

---

## 🚨 Safety Rules

Agents must not:

- Change the on-disk file format silently
- Break backward compatibility of the on-disk format or the public C API
  unintentionally
- Reformat large areas of code
- Submit speculative refactors
- Bypass Gerrit workflow
- Create new build directories unless asked

## 📝 Commit Message Requirements

All commit messages must:

- Strict follow the industry-standard 50/72 rule
- Start with: `MB-XXXXX: Short summary`
- Include a clear explanation of:
  - What changed
  - Why it changed
  - Risk or compatibility impact
- Don't add a 'Co-authored-by' tag for automated agents. The author
  information is already captured in the commit metadata.

Example:

```
MB-12345: Fix off-by-one in filemgr block offset

Correct off-by-one error when computing the offset of the last block
in filemgr_read when the file size is not block aligned.
```

### Change-Id Handling

Do NOT manually add or generate a `Change-Id`.

A local Gerrit commit-msg hook is expected to already be installed and
will automatically add the required `Change-Id` footer when the commit
is created or amended.

Agents must not fabricate or modify the Change-Id.

When amending an existing commit (e.g. to update the commit message
or add further changes), preserve the `Change-Id` line exactly as
it appears in the original commit message. Dropping or replacing the
`Change-Id` on an amended commit would create a new Gerrit review
instead of updating the existing one.

---

## 🧪 Testing Requirements

All functional changes must include:

- New or updated unit tests
- Passing test suite locally
- No unintended regression in on-disk file format compatibility
