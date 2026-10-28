# R19 live sampler race correction

The original strict56 L replay attempt1 stopped after857.260seconds because the controller enumerated `shared.sqlite3-journal`, then SQLite removed it between `is_file()` and `stat()`. The controller stopped its owned container; the complete attempt and scratch remain preserved. This is an instrumentation failure, not a completed L cell or a core performance verdict. No native runtime is changed by this correction.

The failure is independently reproduced in controlled `outputs/cpag-r19-core-live-sampler-race-before.json`. The initial test-import failure remains in `outputs/cpag-r19-core-live-sampler-tests-before.log`; successful focused checks are recorded separately in `outputs/cpag-r19-core-live-sampler-tests-after.log`.

`matrix-live-file-sampler-2` uses one `lstat()` per enumerated entry. Only the exact relative path `result/artifact/shared/shared.sqlite3-journal` may disappear during live sampling. Such a sample records `sample_incomplete=true` and the `vanished` path; its observed byte count is a partial non-atomic sample, not zero bytes for the vanished file or an exact peak. No general temporary suffix exemption is introduced. Disappearing fixed sources/artifacts, permission failures and symlinks still fail. Output limits remain unchanged.

Terminal `physical()` and `file_inventory()` remain unchanged and strict, including for the journal. Native complete-publication verification, complete handoff byte identities and final whole-directory budget checks remain required. Tests cover the old `is_file/stat` race independently, live temporary disappearance, fixed-source/artifact disappearance, permissions and strict terminal disappearance.

The controller versions are `r19-core-fixed-quota-matrix-4` and L-only `r19-core-l-expiry-coverage-5`. Existing frozen runs/views are not modified. A later L replay retry requires a new frozen harness view, the same strict56 native image, explicit CPU-window authorization and the unchanged1800-second/full-resource gates. No retry has been performed by this change.
