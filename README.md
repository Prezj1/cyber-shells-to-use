# OSCP Exam Scripts

Concise Bash helpers for authorized OSCP lab and exam targets only.

## Layout

- `enum/`: the four refactored workflow scripts supplied separately.
- `toolkit/`: the refactored `cyber-shells-to-use` utilities.

Every script supports `-h` and exits without running scans or checking external dependencies:

```bash
./enum/01_workspace_enum.sh -h
./toolkit/web_enum.sh -h
```

The four workflow scripts now default to a relative `./boxes` directory, making them portable between Kali accounts and exam machines. Use `-o ~/boxes` if that is your preferred location.

## Important compatibility change

`toolkit/hash_crack.sh` now uses `-H HASH` for a single hash because `-h` is reserved for help:

```bash
./toolkit/hash_crack.sh -H '5f4dcc3b5aa765d61d8327deb882cf99'
```

## Checks performed

- `bash -n` syntax validation on all 21 scripts.
- `-h` smoke test on all 21 scripts.
- Executable permission applied to every script.

Review commands before use and stay within the authorization and tooling rules for your current environment.
