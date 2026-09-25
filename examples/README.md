# Examples

All example data in this directory is synthetic.

After installing SafeContext locally:

```bash
safecontext protect examples/sample.log
```

This creates a protected log and a local mapping file. The mapping file contains
the original synthetic identifiers and must never be treated as safe for external
processing.

You can simulate an LLM response by copying pseudonyms from the protected file
into another text file and then running:

```bash
safecontext restore analysis.txt -m examples/.sample.safecontext-map.json
```
