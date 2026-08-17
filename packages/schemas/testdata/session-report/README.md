# SessionReport golden corpus

`manifest.json` binds every raw fixture to its expected validation result.
Regenerate the corpus with:

```sh
node packages/schemas/testdata/session-report/generate.mjs
```

The `.raw` extension is intentional: invalid cases include duplicate object
keys, trailing documents, NUL bytes and malformed UTF-8, so JSON formatters
must not rewrite these files.
