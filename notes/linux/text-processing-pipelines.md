# Text Processing Pipelines

This note summarizes common command-line text tools: `grep`, `wc`, `cut`, `sort`, `uniq`, `tr`, `diff`, `join`, `xargs`, and `awk`.

## Pipeline Mental Model

A shell pipeline passes stdout from one command into stdin of the next command:

```bash
command1 | command2 | command3
```

Good pipelines usually do one of these:

- filter rows
- select fields
- normalize text
- sort records
- count or summarize
- format a small report

## Search with `grep`

```bash
grep "ERROR" application.log
grep -n "ERROR" application.log
grep -i "timeout" application.log
grep -E "ERROR|WARN" application.log
```

Use:

- `-n` for line numbers.
- `-i` for case-insensitive matching.
- `-E` for extended regular expressions.
- `-C N` for context around matches.

## Count with `wc`

```bash
wc -l application.log
wc -w notes.md
wc -c payload.bin
```

Use input redirection when you only want the number:

```bash
wc -l < application.log
```

## Select Fields with `cut`

For delimited text:

```bash
cut -d ',' -f 1,3 data.csv
```

For fixed-width text:

```bash
cut -c 1-10 records.txt
```

`cut` is fast and simple, but it does not understand quoted CSV. Use a CSV-aware tool when quoting and escaping matter.

## Sort and Deduplicate

```bash
sort names.txt
sort -n numbers.txt
sort -t ',' -k2,2 data.csv
sort -u names.txt
```

`uniq` only compares adjacent lines, so sort first when global deduplication is needed:

```bash
sort names.txt | uniq
sort names.txt | uniq -c | sort -nr
```

## Normalize Characters with `tr`

Uppercase:

```bash
tr '[:lower:]' '[:upper:]' < input.txt
```

Delete punctuation:

```bash
tr -d '[:punct:]' < input.txt
```

Squeeze repeated spaces:

```bash
tr -s ' ' < input.txt
```

`tr` works at the character level. It does not understand fields, columns, or structured records.

## Compare with `diff`

```bash
diff -u old.txt new.txt
diff -ru old-dir new-dir
```

Use unified diffs for reviewable output.

## Join Two Sorted Files

`join` merges records by a shared key. Inputs must be sorted on the join field.

Example inputs:

```text
1 alice
2 bob
```

```text
1 admin
2 analyst
```

Command:

```bash
join users.txt roles.txt
```

Output:

```text
1 alice admin
2 bob analyst
```

If files are not sorted:

```bash
sort -k1,1 users.txt > users.sorted
sort -k1,1 roles.txt > roles.sorted
join users.sorted roles.sorted
```

## Build Commands with `xargs`

Run a command for each input item:

```bash
printf '%s\n' *.log | xargs -n 1 wc -l
```

Handle spaces safely with null delimiters:

```bash
find logs -type f -name '*.log' -print0 | xargs -0 grep -n "ERROR"
```

Parallelize independent work:

```bash
find data -type f -print0 | xargs -0 -n 1 -P 4 gzip
```

Use parallelism only when tasks are independent and system load is acceptable.

## Analyze with `awk`

Print selected fields:

```bash
awk '{print $1, $3}' records.txt
```

Filter rows:

```bash
awk '$3 > 100 {print $0}' metrics.txt
```

Sum a field:

```bash
awk '{sum += $2} END {print sum}' sizes.txt
```

Use a delimiter:

```bash
awk -F ',' '{print $1, $3}' data.csv
```

## Common Patterns

Top repeated errors:

```bash
grep "ERROR" application.log | sort | uniq -c | sort -nr | head
```

Largest direct children:

```bash
du -h --max-depth=1 /path/to/target | sort -hr
```

Extract a column, remove header, count values:

```bash
cut -d ',' -f 3 data.csv | tail -n +2 | sort | uniq -c | sort -nr
```

Move a sort key to the front, sort, then format:

```bash
awk '{print $3, $1, $2}' records.txt | sort | awk '{print $2, $3, $1}'
```

The transferable lesson is that the shape of each line controls what the next command can easily do.
