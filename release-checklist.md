# Release Checklist

## Overview

This document describes the checklist to publish a release via GitHub workflow.

See [Release Management](./release-management.md) for the overall process of versioning and support.

> [!NOTE]
The maintainers may periodically update this checklist based on feedback.

## Release Steps

Releasing is a two-step process for voting on a specific release, and cutting the release.

### Vote On a Specific Commit

1. Determine a [SemVer2](https://semver.org/)-valid version prefixed with the letter `v` for release. For example, `v1.0.0-alpha.1`, `v1.0.0`.
1. Make sure the dependencies in `go.mod` file are expected by the release.
1. After updating `go.mod` file, run `go mod tidy` to ensure the `go.sum` file is also updated with any potential changes.
1. Determine the commit to be tagged and released.
1. Create an issue for voting with title similar to **"vote**: `tag v1.0.0-alpha.1` with the proposed commit. (see [Issue #204](https://github.com/veraison/go-cose/issues/204)
1. Request a 👍or 👎from each maintainer, requesting details if they voted against, and opening a corresponding issue.
1. Wait a max of 2 weeks for the vote pass, or sooner if a majority of maintainers approve.

### Cut a Release

1. Select [[Draft a new release](https://github.com/veraison/go-cose/releases/new)]
1. **[Choose a tag]**: Create a new tag based on Alpha, RC or a final release: (`v1.0.0-alpha.1`, `v1.0.0-rc.1`, `v1.0.0`).
1. **[Target]**: Select the voted commit in "Recent Commits".
1. **[Previous Tag]**: Select the previous corresponding release.
   1. For alpha and rc releases, select the previous release within that release band (rc.1, select the latest alpha release).
   1. For final releases, select the previous full release: ([v1.3.0](https://github.com/veraison/go-cose/releases/tag/v1.3.0), selects [v1.1.0](https://github.com/veraison/go-cose/releases/tag/v1.1.0))
1. **[Generate Release Notes]**: Edit for spelling and clarity.
1. **[Release title]** Set to the same value as the tag and voted issue.
1. **[Set as a pre-release]**: Set if the release is an alpha or rc.  
   Do not set for final release.
1. **[Set as the latest release]**: To bring focus to the latest, always check this box.
1. Announce the release in the community.
