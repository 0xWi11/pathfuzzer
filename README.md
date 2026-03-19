# path-fuzzer

Burp Suite Montoya API plugin project for fuzzing and request mutation workflows.

## Overview

This repository builds a Burp extension whose entry point is `pzfzr.PathFuzzer`.

The plugin currently includes:

- Request/response capture and persistence
- Route fuzzing
- Parameter fuzzing, deletion, and addition
- Header, cookie, OOB, and cache fuzzing switches
- Swing-based Burp tab UI
- Netty-backed request handling

The build is profile-driven and can produce different branded jars:

- `pathfuzzer` (default profile)
- `oobfuzzer`

## Requirements

- JDK 17
- Maven 3.8+
- Burp Suite with Montoya API support

## Build

Default profile:

```bash
mvn clean package
```

OOB profile:

```bash
mvn clean package -Poobfuzzer
```

Build output is copied to `dist/`.

## Project Layout

- `src/main/java/pzfzr/PathFuzzer.java`: Burp extension entry point
- `src/main/java/pzfzr/gui`: Swing UI panels and Burp tab integration
- `src/main/java/pzfzr/core`: traffic processing, threading, rate limiting, Netty integration
- `src/main/java/pzfzr/fuzzer`: fuzzing modules and payload logic
- `src/main/java/pzfzr/config`: runtime config, persistence, switch management
- `src/main/java/pzfzr/model`: table/view models, export, request-response storage
- `src/main/resources`: profile-injected config and bundled resources

## Notes

- The repository currently has active local development changes. Check `git status` before making unrelated edits.
- Some source comments display as mojibake in the current checkout. Keep file encoding as UTF-8 when editing.
