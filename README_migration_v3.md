# Schema v3 Migration Notes

Changes introduced in schema_version 3:

- Meta object is now strongly typed (struct `Meta`) instead of `map[string]interface{}`.
- SiteResult already typed since v2; legacy map merging removed.
- New field: `http_error` (separate from `head_error`).
- Removed legacy duplicate root map fields inside `site_result` (no parallel map copy).

Impact:
- Any consumer expecting arbitrary meta keys must adapt to explicit fields.
- JSON shape remains similar; all previous meta keys preserved (if populated) but ordering may differ.
- Analysis code updated to unmarshal directly into typed envelope.

Upgrade Steps for External Consumers:
1. Regenerate typed models from JSON if using codegen.
2. Replace dynamic lookups (`meta["kernel_version"]`) with struct fields or typed decoding.
3. Use `http_error` to distinguish GET failures from initial HEAD failures.

Rollback:
- To stay on v2, pin an earlier commit before introduction of Meta struct; outputs will still contain map meta and `schema_version:2`.

Version Matrix:
- v1: legacy map output, mixed dynamic typing.
- v2: typed SiteResult, meta still map.
- v3: typed Meta + typed SiteResult.

Future Work (suggested):
- v4: introduce explicit latency breakdown percentages.
- v4: compress speed samples via delta encoding.
