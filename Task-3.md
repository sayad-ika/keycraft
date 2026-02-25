## Task 3

### First point: restore a deleted branch.

- So the first point is pretty simple, sharing how I did it with proper example:

#### List of branches

```
Craftsmen@Sayad MINGW64 /d/keycraft (doc/task-3)
$ git branch
  doc/stream-of-consciousness
* doc/task-3
  feat/new-feat-3
  feat/new-feature-1
  feat/new-feature-1-rebase
  feat/new-feature-2
  feat/new-feature-2-rebase
  feat/new-feature-3
  feat/new-feature-3-rebase
  feat/version-command
  main
  temp/new-feature-2-rebase
```

#### Now deleting a branch: using this cmd: `git branch -D <branch_name>`

```
Craftsmen@Sayad MINGW64 /d/keycraft (doc/task-3)
$ git branch -D feat/new-feat-3
Deleted branch feat/new-feat-3 (was e6ef5a3).
```

#### Now finding the last HEAD where that the deleted branch was pointing last:

```
Craftsmen@Sayad MINGW64 /d/keycraft (doc/task-3)
$ git reflog
b590f73 (HEAD -> doc/task-3, origin/doc/stream-of-consciousness, doc/stream-of-consciousness) HEAD@{0}: checkout: moving from doc/stream-of-consciousness to doc/task-3
b590f73 (HEAD -> doc/task-3, origin/doc/stream-of-consciousness, doc/stream-of-consciousness) HEAD@{1}: commit: doc: update SOC for final rebase branch
df45b63 HEAD@{2}: commit: doc: update SOC for second-rebased-branch
3bee966 HEAD@{3}: commit: doc: update SOC for first branch rebase
78998d0 HEAD@{4}: commit: doc: update SOC for initial setup for task-2
e6ef5a3 (origin/feat/new-feature-3, feat/new-feature-3) HEAD@{5}: checkout: moving from feat/new-feat-3 to doc/stream-of-consciousness
e6ef5a3 (origin/feat/new-feature-3, feat/new-feature-3) HEAD@{6}: checkout: moving from feat/new-feature-3 to feat/new-feat-3
e6ef5a3 (origin/feat/new-feature-3, feat/new-feature-3) HEAD@{7}: checkout: moving from feat/new-feature-1-rebase to feat/new-feature-3
```

#### As we can see here that `e6ef5a3` is the commit hash that contains the branch that was deleted `feat/new-feat-3`, using this commit hash to move the current HEAD to this (e6ef5a3) commit hash

```
Craftsmen@Sayad MINGW64 /d/keycraft (doc/task-3)
$ git reset e6ef5a3
Unstaged changes after reset:
D       Stream_of_Consciousness.txt
```

#### Lastly checking out to the deleted branch to confirm it was restored:

```
Craftsmen@Sayad MINGW64 /d/keycraft (doc/task-3)
$ git switch feat/new-feature-3
D       Stream_of_Consciousness.txt
Switched to branch 'feat/new-feature-3'
Your branch is up to date with 'origin/feat/new-feature-3'.
```

---

### Second point: create a branch from the old deleted commits:

#### To delete some commits, we could just reset to any previous commit, that delete the latest commits. Now we can use reflog to restore those commits.

#### Contining from the last reset where we restored a deleted branch, we could simply look up current reflog and use those deleted commits to create a new branch:

```
Craftsmen@Sayad MINGW64 /d/keycraft (feat/new-feature-3)
$ git reflog
e6ef5a3 (HEAD -> feat/new-feature-3, origin/feat/new-feature-3, doc/task-3) HEAD@{0}: checkout: moving from doc/task-3 to feat/new-feature-3
e6ef5a3 (HEAD -> feat/new-feature-3, origin/feat/new-feature-3, doc/task-3) HEAD@{1}: reset: moving to e6ef5a3
b590f73 (origin/doc/stream-of-consciousness, doc/stream-of-consciousness) HEAD@{2}: checkout: moving from doc/stream-of-consciousness to doc/task-3
b590f73 (origin/doc/stream-of-consciousness, doc/stream-of-consciousness) HEAD@{3}: commit: doc: update SOC for final rebase branch
df45b63 HEAD@{4}: commit: doc: update SOC for second-rebased-branch
3bee966 HEAD@{5}: commit: doc: update SOC for first branch rebase
78998d0 HEAD@{6}: commit: doc: update SOC for initial setup for task-2
e6ef5a3 (HEAD -> feat/new-feature-3, origin/feat/new-feature-3, doc/task-3) HEAD@{7}: checkout: moving from feat/new-feat-3 to doc/stream-of-consciousness
e6ef5a3 (HEAD -> feat/new-feature-3, origin/feat/new-feature-3, doc/task-3) HEAD@{8}: checkout: moving from feat/new-feature-3 to feat/new-feat-3
e6ef5a3 (HEAD -> feat/new-feature-3, origin/feat/new-feature-3, doc/task-3) HEAD@{9}: checkout: moving from feat/new-feature-1-rebase to feat/new-feature-3
```

#### From the above reflog, we can see that in this commit `b590f73`, we created a new branch, then we reset to `e6ef5a3` hash to restore a deleted branch, by doing so (restoring the deleted branch) we lost some commits (e.g. `b590f73`, `df45b63`, `3bee966`, etc.)

#### Now we'll try to restore them and create a new branch out of it, we can create a new branch from deleted commits using this cmd:

`git checkout -b new-branch-from-deleted-commits <old-commit-hash>`

#### If we were to use switch:

`git switch -c new-branch-from-deleted-commits <old-commit-hash>`,

#### now trying this cmd:

```
Craftsmen@Sayad MINGW64 /d/keycraft (feat/new-feature-3)
$ git switch -c branch-from-deleted-commits b590f73
Switched to a new branch 'branch-from-deleted-commits'

Craftsmen@Sayad MINGW64 /d/keycraft (branch-from-deleted-commits)
$ git log --oneline
b590f73 (HEAD -> branch-from-deleted-commits, origin/doc/stream-of-consciousness, doc/stream-of-consciousness) doc: update SOC for final rebase branch
df45b63 doc: update SOC for second-rebased-branch
3bee966 doc: update SOC for first branch rebase
78998d0 doc: update SOC for initial setup for task-2
e6ef5a3 (origin/feat/new-feature-3, feat/new-feature-3, doc/task-3) chore: update stream of consciousness
```

#### As we can see from above cmd, we branched off to a new branch called `branch-from-deleted-commits`, then from `git log` we can see we restore those delete commits as well. Hence we created a branch from the old deleted commits. :)

---
