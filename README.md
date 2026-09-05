# API archive-reference restoration evidence

Baseline: OpenGeni b4575cc.
Patched source: bd51aa5, including formatting of the archive-storage forwarding.

The before and after screenshots render the complete output of the same desired-success test.
The test fails on the baseline and passes with the patch.
Separate verification also covered viewer attach, missing objects, and corrupt objects.
Raw log files are not included in this public evidence branch.
Tests use a real Docker sandbox and PostgreSQL database with an in-memory ObjectStorage stub.
These are screenshots of recorded test output, not browser UI or real S3 tests.

Command for both captures:

```sh
bun --env-file=/dev/null test --test-name-pattern 'API cold spawner restores a valid object-storage archive ref' ./apps/api/test/rematerialize-archive-ref.test.ts
```

The identical regression file is present in both runs.
Only the baseline-to-patch production source changes between runs.
The primary checkout was restored after each verification sequence.
