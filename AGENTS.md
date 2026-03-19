# AGENTS.md

## Repository Purpose

This is a Java 17 + Maven Burp Suite extension project built on the Montoya API. The main extension class is `pzfzr.PathFuzzer`.

## Working Rules

- Preserve user changes. The worktree may already be dirty.
- Prefer isolated edits. Avoid broad refactors unless requested.
- Keep source files UTF-8. Some existing comments already appear garbled; do not worsen encoding issues.
- Treat this as a plugin project, not a standalone server app.

## Build And Verification

- Default build: `mvn clean package`
- Alternate profile: `mvn clean package -Poobfuzzer`
- Output jar is copied into `dist/`

## Code Map

- `src/main/java/pzfzr/PathFuzzer.java`: extension bootstrap and shutdown
- `src/main/java/pzfzr/core`: request/response interception, concurrency, helpers
- `src/main/java/pzfzr/fuzzer`: mutation engines
- `src/main/java/pzfzr/gui`: Swing panels for Burp UI
- `src/main/java/pzfzr/config`: plugin/profile config and persistence
- `src/main/java/pzfzr/model`: persistence, table data, export

## Editing Guidance

- Be careful around threading and shutdown behavior in `core` and `model`.
- Profile-specific behavior is injected from Maven properties into `src/main/resources/plugin-config.properties`.
- `RequestResponseSaver` is performance-sensitive and currently under active local modification.

## Git Note

In this environment, git may require a one-off safe-directory override:

```bash
git -c safe.directory=C:/dev_project/hellowd/path-fuzzer status
```
