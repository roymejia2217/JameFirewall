#!/usr/bin/env node
"use strict";

const fs = require("fs");
const { PullRequestBody } = require(
  "release-please/build/src/util/pull-request-body.js"
);
const { PullRequestTitle } = require(
  "release-please/build/src/util/pull-request-title.js"
);

function fail(message) {
  process.stderr.write(message + "\n");
  process.exitCode = 1;
  return false;
}

function validate(title, body) {
  const parsedTitle = PullRequestTitle.parse(title);
  if (!parsedTitle?.version) {
    return fail("Release Please title could not be parsed by upstream parser.");
  }
  if (parsedTitle.getTargetBranch() !== "main") {
    return fail("Release Please title must target the main scope.");
  }

  const parsedBody = PullRequestBody.parse(body);
  if (!parsedBody || parsedBody.releaseData.length !== 1) {
    return fail("Release Please body must contain exactly one upstream release entry.");
  }

  const bodyVersion = parsedBody.releaseData[0].version?.toString();
  const titleVersion = parsedTitle.version.toString();
  if (!bodyVersion || bodyVersion !== titleVersion) {
    return fail(
      `Release Please body/title version mismatch: body=${bodyVersion || "<missing>"} title=${titleVersion}`
    );
  }

  if (!parsedBody.header.trim() || !parsedBody.footer.trim()) {
    return fail("Release Please body must preserve upstream header and footer.");
  }

  process.stdout.write(`release_please_version=${titleVersion}\n`);
  return true;
}

function selfTest() {
  const validTitle = "chore(main): release 0.2.0";
  const validBody = `:robot: I have created a release *beep* *boop*
---
## [0.2.0](https://github.com/example/project/compare/v0.1.0...v0.2.0) (2026-09-27)

### Features

* add canonical application icon

---
This PR was generated with [Release Please](https://github.com/googleapis/release-please). See [documentation](https://github.com/googleapis/release-please#release-please).
`;

  if (!validate(validTitle, validBody)) {
    throw new Error("Expected native Release Please body to pass.");
  }

  const originalExitCode = process.exitCode;
  process.exitCode = 0;
  const humanBody = `## What

Prepare release 0.2.0.

## Why

Publish the approved release.

## Testing

Required CI passed.

## Related issues

None.
`;
  if (validate(validTitle, humanBody)) {
    throw new Error("Expected human PR template to fail Release Please parsing.");
  }
  process.exitCode = originalExitCode || 0;

  if (validate("chore(main): release 0.3.0", validBody)) {
    throw new Error("Expected title/body version mismatch to fail.");
  }
  process.exitCode = originalExitCode || 0;

  process.stdout.write("Release Please upstream body governance contract: ok\n");
}

function parseArgs(argv) {
  const args = { selfTest: false, bodyFile: null, title: null };
  for (let i = 2; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--self-test") {
      args.selfTest = true;
    } else if (arg === "--body-file") {
      args.bodyFile = argv[++i];
    } else if (arg === "--title") {
      args.title = argv[++i];
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }
  return args;
}

const args = parseArgs(process.argv);
if (args.selfTest) {
  selfTest();
} else {
  if (!args.bodyFile || !args.title) {
    throw new Error("--body-file and --title are required.");
  }
  const body = fs.readFileSync(args.bodyFile, "utf8");
  if (!validate(args.title, body)) {
    process.exit(1);
  }
}
