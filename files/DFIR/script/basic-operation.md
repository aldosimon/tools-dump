## file operation, prettyfy etc.

### gzip deflate

```gzip -d <file.ext.gz>```

### json to jq

```for file in *.json; do jq . "$file" > "$file.tmp" && mv "$file.tmp" "$file"; done```

## grep

### grep and show after, before lines

show lines before, after, and context (before and after). Replace B (before) with A (after), or C (context)

```grep -B 2 "error" log.txt```