# flynn

- Find indicators of weaponized git repositories
- Able to be plugged into a CI/CD pipeline
- Or run as a command line tool. 
- SARIF output supported
- Risk scoring: `INFO, MEDIUM, HIGH, CRITICAL`

# checks
## config-based command execution

- core.fsmonitor — shell command exec on git status, git add, git commit etc
- core.fsmonitorv2 — newer protocol variant, same primitive
- core.sshCommand — exec on any remote op over SSH
- core.gitProxy — exec when connecting via git protocol
- core.editor — exec on git commit, git rebase -i
- sequence.editor — exec specifically on git rebase -i
- diff.external — exec on git diff
- diff.tool / difftool.<name>.cmd — exec on git difftool
- merge.tool / mergetool.<name>.cmd — exec on git mergetool
- credential.helper — exec on any auth operation
- pager.<cmd> — exec when output is paged (git log, git diff, etc)
- filter.<name>.clean — exec on git add for matching files
- filter.<name>.smudge — exec on git checkout for matching files
- filter.<name>.process — long-running filter process variant
- gpg.program — exec on signed commits/tags
- gpg.ssh.program — SSH signing variant
- gpg.x509.program — x509 signing variant
- receive.procReceive — server-side hook on push
- uploadpack.packObjectsHook — exec during git fetch/git clone from this repo
- transfer.fsckObjects — combined with crafted objects
- core.pager — global pager override, exec on any paged output
- web.browser — exec when git tries to open a browser
- sendemail.smtpserver — exec via git send-email
- include.path — load external config, chains into any of the above
- includeIf.*.path — conditional external config load (gitdir, onbranch, hasconfig variants)


## hook abuse

- Executable files in .git/hooks/ with canonical names — pre-commit, post-commit, pre-push, post-checkout, post-merge, post-rewrite, prepare-commit-msg, commit-msg, pre-rebase, pre-auto-gc, post-update, pre-receive, update, proc-receive, push-to-checkout, fsmonitor-watchman, p4-pre-submit, p4-prepare-changelist, p4-changelist, p4-post-changelist
- Non-.sample hooks present at all (clean repos only have .sample files)
- World-writable hook files — privilege escalation if another user runs git
- Hooks with unusual shebangs (#!/usr/bin/env python3, #!/usr/bin/env node, #!/usr/bin/perl — not inherently malicious but worth flagging)
- Hooks that are symlinks pointing outside the repo
- core.hooksPath redirecting to attacker-controlled directory
- Hooks present in a custom core.hooksPath location


## structural anomalies

- Buried bare repo — directory containing HEAD + objects/ + refs/ with no .git parent (OVE-20210718-0001)
- core.bare = false combined with core.worktree — the jailbreak pattern that makes a buried bare repo functional
- .git as a file rather than directory, containing gitdir: <path> — redirects git dir to attacker-controlled location
- gitdir: path in .git file pointing outside the repo or to an absolute path
- core.worktree pointing outside the repo root
- core.hooksPath pointing to an absolute path or path outside the repo
- Symlinks within .git/ pointing outside the repo
- .git/ directory that is itself a symlink
- Unexpected subdirectories inside .git/ that aren't part of standard git layout
- .git/config containing multiple [core] sections — can be used to confuse parsers


## object store anomalies

- Oversized loose objects — blobs above a configurable threshold (e.g. >1MB) in .git/objects/
- Binary blobs in the object store not referenced by any tree
- Orphaned objects not reachable from any ref — potential payload staging
- Crafted .git/index file — Driver Tom's arbitrary write primitive, abused by git pillagers
- Unusually large .git/index
- Objects with path-traversal-like names embedded in trees (CVE-2014-9390 class — null bytes, .., mixed case .Git on case-insensitive FS)
- Pack files (.git/objects/pack/*.pack) that are unusually large
- .git/objects/info/alternates — redirects object lookups to external path, enables object injection
- .git/objects/info/http-alternates — same but fetched over HTTP at runtime


## refs and HEAD anomalies

- HEAD pointing to a non-existent ref
- HEAD containing a raw SHA instead of a symbolic ref — valid but unusual, flag it
- Refs with path-traversal characters in their names
- Refs in .git/refs/ pointing to non-existent objects
- packed-refs containing refs with unusual or suspicious names
- FETCH_HEAD, MERGE_HEAD, CHERRY_PICK_HEAD, REVERT_HEAD present unexpectedly — indicates interrupted operations, may indicate a state manipulation attempt
- ORIG_HEAD pointing to unexpected commit
- Ref names containing null bytes, newlines, or other control characters


## gitattributes abuse

- .gitattributes or .git/info/attributes assigning filter= to files — triggers filter.<name>.smudge/clean on checkout/add
- diff= attribute assignments — triggers diff.<name>.textconv or diff.external
- merge= attribute assignments — triggers merge.<name>.driver
- Attributes targeting high-value filenames — Makefile, *.sh, *.py, *.rs, *.go, build.gradle, CMakeLists.txt
- Attributes with eol= combined with filter hooks
- export-subst attribute — substitutes variables into file content on archive, lower severity but unusual
- ident attribute — lower severity, substitutes $Id$ into files


## worktree and alternates

- .git/worktrees/ entries present at all — flag for review
- .git/worktrees/<name>/gitdir pointing outside expected path
- .git/worktrees/<name>/commondir pointing to unexpected location
- Multiple worktrees registered pointing to sensitive filesystem locations


## submodule abuse

- .gitmodules present with url = pointing to a file:// path — local filesystem access
- .gitmodules with update = !command — arbitrary command exec on git submodule update
- Submodule url using unusual schemes (ext::, fd::)
- Submodule paths with .. components — path traversal
- .git/modules/ containing nested repos with their own malicious configs — each one recurse-check


## info and metadata

- .git/info/sparse-checkout with unusual glob patterns
- .git/info/exclude — lower severity, attacker hiding their own tracks
- .git/description modified from default — low severity, indicates tampering, useful fingerprint
- .git/config with unexpected [user] section — attacker identity leak or impersonation setup
- Unexpected [remote] entries pointing to unusual URLs or local paths
- [remote] pushurl differing from url — silent redirect of pushes
- Remote URLs using ext:: protocol — arbitrary command exec on remote operations
- Remote URLs using fd:: protocol
- Remote URLs pointing to file:// paths outside the expected location


## encoding and evasion

- Config keys with unusual whitespace or tab indentation tricks
- Unicode homoglyphs in config key names — attempting to visually spoof a safe key
- Null bytes in config values
- Extremely long config values — potential buffer handling edge cases in tooling
- Config values with shell metacharacters in ostensibly non-exec fields
- Binary content in .git/config — shouldn't be there at all

# Output formats

- text to console (always unless --quiet)
- text to file
- json to file
- sarif to file
