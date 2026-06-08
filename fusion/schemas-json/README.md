# Generated JSON Schemas

These files are produced from the Pydantic models in `src/fusion/schemas/`.

**Do not hand-edit.** Regenerate after every model change:

```bash
# via the installed entry point
fusion-export-schemas

# or directly from the source tree
PYTHONPATH=src python scripts/export_schemas.py
```

Consumers in other languages (Rust collectors, TypeScript portals, ...) should treat the JSON Schema files in this directory as the authoritative wire contract.
