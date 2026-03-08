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

## Full reflog history


```
c0b1cc6 (HEAD -> branch-from-deleted-commits, origin/branch-from-deleted-commits) HEAD@{0}: checkout: moving from feat/new-feature-3 to branch-from-deleted-commits
2c7c43d (origin/feat/new-feature-3, feat/new-feature-3) HEAD@{1}: checkout: moving from feat/new-feature-2 to feat/new-feature-3
3b30fbe (origin/feat/new-feature-2, feat/new-feature-2) HEAD@{2}: checkout: moving from feat/new-feature-3 to feat/new-feature-2
2c7c43d (origin/feat/new-feature-3, feat/new-feature-3) HEAD@{3}: rebase (finish): returning to refs/heads/feat/new-feature-3
2c7c43d (origin/feat/new-feature-3, feat/new-feature-3) HEAD@{4}: rebase (squash): feat: add short flag for version cmd and update README.md file to include example
a15d5bb HEAD@{5}: rebase (squash): # This is a combination of 2 commits.
f867ddc HEAD@{6}: rebase (pick): feat: add short flag for version cmd
33d2dfe HEAD@{7}: rebase (squash): feat: add password strength hint for update password
fb3af1a HEAD@{8}: rebase (start): checkout 3b30fbe
d7e1bb3 HEAD@{9}: rebase (finish): returning to refs/heads/feat/new-feature-3
d7e1bb3 HEAD@{10}: rebase (pick): chore: update stream of consciousness
3f1610b HEAD@{11}: rebase (pick): doc: update README.md file to include another example
48c94ad HEAD@{12}: rebase (pick): feat: add short flag for version cmd
bedc82c HEAD@{13}: rebase (pick): chore: update stream of consciousness
fb3af1a HEAD@{14}: rebase (pick): feat: add password strength hint for update password
e56bd7e HEAD@{15}: rebase (pick): feat: add a hint for password strength
3b30fbe (origin/feat/new-feature-2, feat/new-feature-2) HEAD@{16}: rebase (start): checkout feat/new-feature-2
e6ef5a3 (doc/task-3) HEAD@{17}: rebase (abort): returning to refs/heads/feat/new-feature-3
11d987c HEAD@{18}: rebase (continue): feat: add verification for backup
3b30fbe (origin/feat/new-feature-2, feat/new-feature-2) HEAD@{19}: rebase (start): checkout feat/new-feature-2
e6ef5a3 (doc/task-3) HEAD@{20}: checkout: moving from feat/new-feature-2 to feat/new-feature-3
3b30fbe (origin/feat/new-feature-2, feat/new-feature-2) HEAD@{21}: rebase (finish): returning to refs/heads/feat/new-feature-2
3b30fbe (origin/feat/new-feature-2, feat/new-feature-2) HEAD@{22}: rebase (squash): test: add test case for sort flag and update README.md file to add additional examples
5762fac HEAD@{23}: rebase (start): checkout d7060b
47cb00a HEAD@{24}: rebase (finish): returning to refs/heads/feat/new-feature-2
47cb00a HEAD@{25}: rebase (pick): doc: update README.md file to add additional examples
5762fac HEAD@{26}: rebase (pick): test: add test case for sort flag
a1c5d3c HEAD@{27}: rebase (pick): feat: add sort flag for list option
26ab7b1 HEAD@{28}: rebase (squash): feat: add --masked-password flag to show a partial password, add test and update README.md
67d4286 HEAD@{29}: rebase (squash): # This is a combination of 2 commits.
3d5e250 HEAD@{30}: rebase (start): checkout d7060be
1a55d38 HEAD@{31}: rebase (finish): returning to refs/heads/feat/new-feature-2
1a55d38 HEAD@{32}: rebase (pick): doc: update README.md file to add additional examples
4a9e699 HEAD@{33}: rebase (pick): test: add test case for sort flag
f56efbb HEAD@{34}: rebase (pick): feat: add sort flag for list option
d92d0d5 HEAD@{35}: rebase (pick): doc: update README.md to add a new example of the --masked-password flag
71ec570 HEAD@{36}: rebase (pick): test: add test for --masked-password flag
3d5e250 HEAD@{37}: rebase (pick): feat: add --masked-password flag to show a partial password
d7060be (origin/feat/new-feature-1, feat/new-feature-1) HEAD@{38}: rebase (start): checkout feat/new-feature-1
563dc8e HEAD@{39}: checkout: moving from feat/new-feature-1 to feat/new-feature-2
d7060be (origin/feat/new-feature-1, feat/new-feature-1) HEAD@{40}: rebase (finish): returning to refs/heads/feat/new-feature-1
d7060be (origin/feat/new-feature-1, feat/new-feature-1) HEAD@{41}: rebase (squash): feat: add --count flag to the generate function to specify number of passwords to generate and update README.md
cac313f HEAD@{42}: rebase (pick): feat: add --count flag to the generate function to specify number of passwords to generate
b0917b8 HEAD@{43}: rebase (squash): feat: add 'yes' as alias of force for delete operation and update README.md
0f429c9 HEAD@{44}: rebase (pick): feat: add 'yes' as alias of force for delete operation
2c933b4 HEAD@{45}: rebase (squash): feat: add verification for backup
bade296 HEAD@{46}: rebase (start): checkout 0248c97
013756f HEAD@{47}: checkout: moving from branch-from-deleted-commits to feat/new-feature-1
c0b1cc6 (HEAD -> branch-from-deleted-commits, origin/branch-from-deleted-commits) HEAD@{48}: commit: task: restore a deleted branch and created a branch from old deleted commits
b590f73 (origin/doc/stream-of-consciousness, doc/stream-of-consciousness) HEAD@{49}: checkout: moving from feat/new-feature-3 to branch-from-deleted-commits
e6ef5a3 (doc/task-3) HEAD@{50}: checkout: moving from doc/task-3 to feat/new-feature-3
e6ef5a3 (doc/task-3) HEAD@{51}: reset: moving to e6ef5a3
b590f73 (origin/doc/stream-of-consciousness, doc/stream-of-consciousness) HEAD@{52}: checkout: moving from doc/stream-of-consciousness to doc/task-3
b590f73 (origin/doc/stream-of-consciousness, doc/stream-of-consciousness) HEAD@{53}: commit: doc: update SOC for final rebase branch
df45b63 HEAD@{54}: commit: doc: update SOC for second-rebased-branch
3bee966 HEAD@{55}: commit: doc: update SOC for first branch rebase
78998d0 HEAD@{56}: commit: doc: update SOC for initial setup for task-2
e6ef5a3 (doc/task-3) HEAD@{57}: checkout: moving from feat/new-feat-3 to doc/stream-of-consciousness
e6ef5a3 (doc/task-3) HEAD@{58}: checkout: moving from feat/new-feature-3 to feat/new-feat-3
e6ef5a3 (doc/task-3) HEAD@{59}: checkout: moving from feat/new-feature-1-rebase to feat/new-feature-3
b3893ef (origin/feat/new-feature-1-rebase, feat/new-feature-1-rebase) HEAD@{60}: checkout: moving from feat/new-feature-3-rebase to feat/new-feature-1-rebase
e61759a (origin/feat/new-feature-3-rebase, feat/new-feature-3-rebase) HEAD@{61}: checkout: moving from feat/new-feature-2-rebase to feat/new-feature-3-rebase
3e7d1fd (origin/feat/new-feature-2-rebase, temp/new-feature-2-rebase, feat/new-feature-2-rebase) HEAD@{62}: reset: moving to HEAD
3e7d1fd (origin/feat/new-feature-2-rebase, temp/new-feature-2-rebase, feat/new-feature-2-rebase) HEAD@{63}: reset: moving to 3e7d1fd
e61759a (origin/feat/new-feature-3-rebase, feat/new-feature-3-rebase) HEAD@{64}: checkout: moving from feat/new-feature-3-rebase to feat/new-feature-2-rebase
e61759a (origin/feat/new-feature-3-rebase, feat/new-feature-3-rebase) HEAD@{65}: rebase (finish): returning to refs/heads/feat/new-feature-3-rebase
e61759a (origin/feat/new-feature-3-rebase, feat/new-feature-3-rebase) HEAD@{66}: rebase (squash): doc: update README.md file to include another example
b0b35d6 HEAD@{67}: rebase (start): checkout 383a005
925f24f HEAD@{68}: rebase (finish): returning to refs/heads/feat/new-feature-3-rebase
925f24f HEAD@{69}: rebase (pick): chore: update stream of consciousness
:
b590f73 (origin/doc/stream-of-consciousness, doc/stream-of-consciousness) HEAD@{49}: checkout: moving from feat/new-feature-3 to branch-from-deleted-commits
e6ef5a3 (doc/task-3) HEAD@{50}: checkout: moving from doc/task-3 to feat/new-feature-3
e6ef5a3 (doc/task-3) HEAD@{51}: reset: moving to e6ef5a3
b590f73 (origin/doc/stream-of-consciousness, doc/stream-of-consciousness) HEAD@{52}: checkout: moving from doc/stream-of-consciousness to doc/task-3
b590f73 (origin/doc/stream-of-consciousness, doc/stream-of-consciousness) HEAD@{53}: commit: doc: update SOC for final rebase branch
df45b63 HEAD@{54}: commit: doc: update SOC for second-rebased-branch
3bee966 HEAD@{55}: commit: doc: update SOC for first branch rebase
78998d0 HEAD@{56}: commit: doc: update SOC for initial setup for task-2
e6ef5a3 (doc/task-3) HEAD@{57}: checkout: moving from feat/new-feat-3 to doc/stream-of-consciousness
e6ef5a3 (doc/task-3) HEAD@{58}: checkout: moving from feat/new-feature-3 to feat/new-feat-3
e6ef5a3 (doc/task-3) HEAD@{59}: checkout: moving from feat/new-feature-1-rebase to feat/new-feature-3
b3893ef (origin/feat/new-feature-1-rebase, feat/new-feature-1-rebase) HEAD@{60}: checkout: moving from feat/new-feature-3-rebase to feat/new-feature-1-rebase
e61759a (origin/feat/new-feature-3-rebase, feat/new-feature-3-rebase) HEAD@{61}: checkout: moving from feat/new-feature-2-rebase to feat/new-feature-3-rebase
3e7d1fd (origin/feat/new-feature-2-rebase, temp/new-feature-2-rebase, feat/new-feature-2-rebase) HEAD@{62}: reset: moving to HEAD
3e7d1fd (origin/feat/new-feature-2-rebase, temp/new-feature-2-rebase, feat/new-feature-2-rebase) HEAD@{63}: reset: moving to 3e7d1fd
e61759a (origin/feat/new-feature-3-rebase, feat/new-feature-3-rebase) HEAD@{64}: checkout: moving from feat/new-feature-3-rebase to feat/new-feature-2-rebase
e61759a (origin/feat/new-feature-3-rebase, feat/new-feature-3-rebase) HEAD@{65}: rebase (finish): returning to refs/heads/feat/new-feature-3-rebase
e61759a (origin/feat/new-feature-3-rebase, feat/new-feature-3-rebase) HEAD@{66}: rebase (squash): doc: update README.md file to include another example
b0b35d6 HEAD@{67}: rebase (start): checkout 383a005
925f24f HEAD@{68}: rebase (finish): returning to refs/heads/feat/new-feature-3-rebase
925f24f HEAD@{69}: rebase (pick): chore: update stream of consciousness
b0b35d6 HEAD@{70}: rebase (pick): doc: update README.md file to include another example
:
b590f73 (origin/doc/stream-of-consciousness, doc/stream-of-consciousness) HEAD@{49}: checkout: moving from feat/new-feature-3 to branch-from-deleted-commits
e6ef5a3 (doc/task-3) HEAD@{50}: checkout: moving from doc/task-3 to feat/new-feature-3
e6ef5a3 (doc/task-3) HEAD@{51}: reset: moving to e6ef5a3
b590f73 (origin/doc/stream-of-consciousness, doc/stream-of-consciousness) HEAD@{52}: checkout: moving from doc/stream-of-consciousness to doc/task-3
b590f73 (origin/doc/stream-of-consciousness, doc/stream-of-consciousness) HEAD@{53}: commit: doc: update SOC for final rebase branch
df45b63 HEAD@{54}: commit: doc: update SOC for second-rebased-branch
3bee966 HEAD@{55}: commit: doc: update SOC for first branch rebase
78998d0 HEAD@{56}: commit: doc: update SOC for initial setup for task-2
e6ef5a3 (doc/task-3) HEAD@{57}: checkout: moving from feat/new-feat-3 to doc/stream-of-consciousness
e6ef5a3 (doc/task-3) HEAD@{58}: checkout: moving from feat/new-feature-3 to feat/new-feat-3
e6ef5a3 (doc/task-3) HEAD@{59}: checkout: moving from feat/new-feature-1-rebase to feat/new-feature-3
b3893ef (origin/feat/new-feature-1-rebase, feat/new-feature-1-rebase) HEAD@{60}: checkout: moving from feat/new-feature-3-rebase to feat/new-feature-1-rebase
e61759a (origin/feat/new-feature-3-rebase, feat/new-feature-3-rebase) HEAD@{61}: checkout: moving from feat/new-feature-2-rebase to feat/new-feature-3-rebase
3e7d1fd (origin/feat/new-feature-2-rebase, temp/new-feature-2-rebase, feat/new-feature-2-rebase) HEAD@{62}: reset: moving to HEAD
3e7d1fd (origin/feat/new-feature-2-rebase, temp/new-feature-2-rebase, feat/new-feature-2-rebase) HEAD@{63}: reset: moving to 3e7d1fd
e61759a (origin/feat/new-feature-3-rebase, feat/new-feature-3-rebase) HEAD@{64}: checkout: moving from feat/new-feature-3-rebase to feat/new-feature-2-rebase
e61759a (origin/feat/new-feature-3-rebase, feat/new-feature-3-rebase) HEAD@{65}: rebase (finish): returning to refs/heads/feat/new-feature-3-rebase
e61759a (origin/feat/new-feature-3-rebase, feat/new-feature-3-rebase) HEAD@{66}: rebase (squash): doc: update README.md file to include another example
b0b35d6 HEAD@{67}: rebase (start): checkout 383a005
925f24f HEAD@{68}: rebase (finish): returning to refs/heads/feat/new-feature-3-rebase
925f24f HEAD@{69}: rebase (pick): chore: update stream of consciousness
b0b35d6 HEAD@{70}: rebase (pick): doc: update README.md file to include another example
383a005 HEAD@{71}: rebase (pick): feat: add short flag for version cmd
c5e1156 HEAD@{72}: rebase (squash): feat: add a hint for password strength
ef0c117 HEAD@{73}: rebase (squash): # This is a combination of 2 commits.
32f9ec0 HEAD@{74}: rebase (start): checkout 3e7d1fd
4cf11f7 HEAD@{75}: rebase (finish): returning to refs/heads/feat/new-feature-3-rebase
4cf11f7 HEAD@{76}: rebase (pick): chore: update stream of consciousness
fd5b8c6 HEAD@{77}: rebase (pick): doc: update README.md file to include another example
8486581 HEAD@{78}: rebase (pick): feat: add short flag for version cmd
3d8a8a5 HEAD@{79}: rebase (pick): chore: update stream of consciousness
:
b590f73 (origin/doc/stream-of-consciousness, doc/stream-of-consciousness) HEAD@{49}: checkout: moving from feat/new-feature-3 to branch-from-deleted-commits
e6ef5a3 (doc/task-3) HEAD@{50}: checkout: moving from doc/task-3 to feat/new-feature-3
e6ef5a3 (doc/task-3) HEAD@{51}: reset: moving to e6ef5a3
b590f73 (origin/doc/stream-of-consciousness, doc/stream-of-consciousness) HEAD@{52}: checkout: moving from doc/stream-of-consciousness to doc/task-3
b590f73 (origin/doc/stream-of-consciousness, doc/stream-of-consciousness) HEAD@{53}: commit: doc: update SOC for final rebase branch
df45b63 HEAD@{54}: commit: doc: update SOC for second-rebased-branch
3bee966 HEAD@{55}: commit: doc: update SOC for first branch rebase
78998d0 HEAD@{56}: commit: doc: update SOC for initial setup for task-2
e6ef5a3 (doc/task-3) HEAD@{57}: checkout: moving from feat/new-feat-3 to doc/stream-of-consciousness
e6ef5a3 (doc/task-3) HEAD@{58}: checkout: moving from feat/new-feature-3 to feat/new-feat-3
e6ef5a3 (doc/task-3) HEAD@{59}: checkout: moving from feat/new-feature-1-rebase to feat/new-feature-3
b3893ef (origin/feat/new-feature-1-rebase, feat/new-feature-1-rebase) HEAD@{60}: checkout: moving from feat/new-feature-3-rebase to feat/new-feature-1-rebase
e61759a (origin/feat/new-feature-3-rebase, feat/new-feature-3-rebase) HEAD@{61}: checkout: moving from feat/new-feature-2-rebase to feat/new-feature-3-rebase
3e7d1fd (origin/feat/new-feature-2-rebase, temp/new-feature-2-rebase, feat/new-feature-2-rebase) HEAD@{62}: reset: moving to HEAD
3e7d1fd (origin/feat/new-feature-2-rebase, temp/new-feature-2-rebase, feat/new-feature-2-rebase) HEAD@{63}: reset: moving to 3e7d1fd
e61759a (origin/feat/new-feature-3-rebase, feat/new-feature-3-rebase) HEAD@{64}: checkout: moving from feat/new-feature-3-rebase to feat/new-feature-2-rebase
e61759a (origin/feat/new-feature-3-rebase, feat/new-feature-3-rebase) HEAD@{65}: rebase (finish): returning to refs/heads/feat/new-feature-3-rebase
e61759a (origin/feat/new-feature-3-rebase, feat/new-feature-3-rebase) HEAD@{66}: rebase (squash): doc: update README.md file to include another example
b0b35d6 HEAD@{67}: rebase (start): checkout 383a005
925f24f HEAD@{68}: rebase (finish): returning to refs/heads/feat/new-feature-3-rebase
925f24f HEAD@{69}: rebase (pick): chore: update stream of consciousness
b0b35d6 HEAD@{70}: rebase (pick): doc: update README.md file to include another example
383a005 HEAD@{71}: rebase (pick): feat: add short flag for version cmd
c5e1156 HEAD@{72}: rebase (squash): feat: add a hint for password strength
ef0c117 HEAD@{73}: rebase (squash): # This is a combination of 2 commits.
32f9ec0 HEAD@{74}: rebase (start): checkout 3e7d1fd
4cf11f7 HEAD@{75}: rebase (finish): returning to refs/heads/feat/new-feature-3-rebase
4cf11f7 HEAD@{76}: rebase (pick): chore: update stream of consciousness
fd5b8c6 HEAD@{77}: rebase (pick): doc: update README.md file to include another example
8486581 HEAD@{78}: rebase (pick): feat: add short flag for version cmd
3d8a8a5 HEAD@{79}: rebase (pick): chore: update stream of consciousness
bdef875 HEAD@{80}: rebase (pick): feat: add password strength hint for update password
32f9ec0 HEAD@{81}: rebase (pick): feat: add a hint for password strength
3e7d1fd (origin/feat/new-feature-2-rebase, temp/new-feature-2-rebase, feat/new-feature-2-rebase) HEAD@{82}: rebase (start): checkout temp/new-feature-2-rebase
e6ef5a3 (doc/task-3) HEAD@{83}: checkout: moving from feat/new-feature-1-rebase to feat/new-feature-3-rebase
b3893ef (origin/feat/new-feature-1-rebase, feat/new-feature-1-rebase) HEAD@{84}: checkout: moving from temp/new-feature-2-rebase to feat/new-feature-1-rebase
3e7d1fd (origin/feat/new-feature-2-rebase, temp/new-feature-2-rebase, feat/new-feature-2-rebase) HEAD@{85}: rebase (finish): returning to refs/heads/temp/new-feature-2-rebase
3e7d1fd (origin/feat/new-feature-2-rebase, temp/new-feature-2-rebase, feat/new-feature-2-rebase) HEAD@{86}: rebase (squash): test: add test case for sort flag
400aaca HEAD@{87}: rebase (pick): test: add test case for sort flag
988557d HEAD@{88}: rebase (pick): feat: add sort flag for list option
41a9dc3 HEAD@{89}: rebase (squash): feat: add --masked-password flag to show a partial password
8a70371 HEAD@{90}: rebase (squash): # This is a combination of 2 commits.
:
b590f73 (origin/doc/stream-of-consciousness, doc/stream-of-consciousness) HEAD@{49}: checkout: moving from feat/new-feature-3 to branch-from-deleted-commits
e6ef5a3 (doc/task-3) HEAD@{50}: checkout: moving from doc/task-3 to feat/new-feature-3
e6ef5a3 (doc/task-3) HEAD@{51}: reset: moving to e6ef5a3
b590f73 (origin/doc/stream-of-consciousness, doc/stream-of-consciousness) HEAD@{52}: checkout: moving from doc/stream-of-consciousness to doc/task-3
b590f73 (origin/doc/stream-of-consciousness, doc/stream-of-consciousness) HEAD@{53}: commit: doc: update SOC for final rebase branch
df45b63 HEAD@{54}: commit: doc: update SOC for second-rebased-branch
3bee966 HEAD@{55}: commit: doc: update SOC for first branch rebase
78998d0 HEAD@{56}: commit: doc: update SOC for initial setup for task-2
e6ef5a3 (doc/task-3) HEAD@{57}: checkout: moving from feat/new-feat-3 to doc/stream-of-consciousness
e6ef5a3 (doc/task-3) HEAD@{58}: checkout: moving from feat/new-feature-3 to feat/new-feat-3
e6ef5a3 (doc/task-3) HEAD@{59}: checkout: moving from feat/new-feature-1-rebase to feat/new-feature-3
b3893ef (origin/feat/new-feature-1-rebase, feat/new-feature-1-rebase) HEAD@{60}: checkout: moving from feat/new-feature-3-rebase to feat/new-feature-1-rebase
e61759a (origin/feat/new-feature-3-rebase, feat/new-feature-3-rebase) HEAD@{61}: checkout: moving from feat/new-feature-2-rebase to feat/new-feature-3-rebase
3e7d1fd (origin/feat/new-feature-2-rebase, temp/new-feature-2-rebase, feat/new-feature-2-rebase) HEAD@{62}: reset: moving to HEAD
3e7d1fd (origin/feat/new-feature-2-rebase, temp/new-feature-2-rebase, feat/new-feature-2-rebase) HEAD@{63}: reset: moving to 3e7d1fd
e61759a (origin/feat/new-feature-3-rebase, feat/new-feature-3-rebase) HEAD@{64}: checkout: moving from feat/new-feature-3-rebase to feat/new-feature-2-rebase
e61759a (origin/feat/new-feature-3-rebase, feat/new-feature-3-rebase) HEAD@{65}: rebase (finish): returning to refs/heads/feat/new-feature-3-rebase
e61759a (origin/feat/new-feature-3-rebase, feat/new-feature-3-rebase) HEAD@{66}: rebase (squash): doc: update README.md file to include another example
b0b35d6 HEAD@{67}: rebase (start): checkout 383a005
925f24f HEAD@{68}: rebase (finish): returning to refs/heads/feat/new-feature-3-rebase
925f24f HEAD@{69}: rebase (pick): chore: update stream of consciousness
b0b35d6 HEAD@{70}: rebase (pick): doc: update README.md file to include another example
383a005 HEAD@{71}: rebase (pick): feat: add short flag for version cmd
c5e1156 HEAD@{72}: rebase (squash): feat: add a hint for password strength
ef0c117 HEAD@{73}: rebase (squash): # This is a combination of 2 commits.
32f9ec0 HEAD@{74}: rebase (start): checkout 3e7d1fd
4cf11f7 HEAD@{75}: rebase (finish): returning to refs/heads/feat/new-feature-3-rebase
4cf11f7 HEAD@{76}: rebase (pick): chore: update stream of consciousness
fd5b8c6 HEAD@{77}: rebase (pick): doc: update README.md file to include another example
8486581 HEAD@{78}: rebase (pick): feat: add short flag for version cmd
3d8a8a5 HEAD@{79}: rebase (pick): chore: update stream of consciousness
bdef875 HEAD@{80}: rebase (pick): feat: add password strength hint for update password
32f9ec0 HEAD@{81}: rebase (pick): feat: add a hint for password strength
3e7d1fd (origin/feat/new-feature-2-rebase, temp/new-feature-2-rebase, feat/new-feature-2-rebase) HEAD@{82}: rebase (start): checkout temp/new-feature-2-rebase
e6ef5a3 (doc/task-3) HEAD@{83}: checkout: moving from feat/new-feature-1-rebase to feat/new-feature-3-rebase
b3893ef (origin/feat/new-feature-1-rebase, feat/new-feature-1-rebase) HEAD@{84}: checkout: moving from temp/new-feature-2-rebase to feat/new-feature-1-rebase
3e7d1fd (origin/feat/new-feature-2-rebase, temp/new-feature-2-rebase, feat/new-feature-2-rebase) HEAD@{85}: rebase (finish): returning to refs/heads/temp/new-feature-2-rebase
3e7d1fd (origin/feat/new-feature-2-rebase, temp/new-feature-2-rebase, feat/new-feature-2-rebase) HEAD@{86}: rebase (squash): test: add test case for sort flag
400aaca HEAD@{87}: rebase (pick): test: add test case for sort flag
988557d HEAD@{88}: rebase (pick): feat: add sort flag for list option
41a9dc3 HEAD@{89}: rebase (squash): feat: add --masked-password flag to show a partial password
8a70371 HEAD@{90}: rebase (squash): # This is a combination of 2 commits.
19ce9ce HEAD@{91}: rebase (start): checkout b3893ef
29a93a7 HEAD@{92}: rebase (finish): returning to refs/heads/temp/new-feature-2-rebase
29a93a7 HEAD@{93}: rebase (pick): doc: update README.md file to add additional examples
826807f HEAD@{94}: rebase (pick): test: add test case for sort flag
064b81a HEAD@{95}: rebase (pick): feat: add sort flag for list option
415a4e6 HEAD@{96}: rebase (pick): doc: update README.md to add a new example of the --masked-password flag
37d91ff HEAD@{97}: rebase (pick): test: add test for --masked-password flag
19ce9ce HEAD@{98}: rebase (pick): feat: add --masked-password flag to show a partial password
b3893ef (origin/feat/new-feature-1-rebase, feat/new-feature-1-rebase) HEAD@{99}: rebase (start): checkout feat/new-feature-1-rebase
563dc8e HEAD@{100}: rebase (abort): returning to refs/heads/temp/new-feature-2-rebase
b3893ef (origin/feat/new-feature-1-rebase, feat/new-feature-1-rebase) HEAD@{101}: rebase (start): checkout feat/new-feature-1-rebase
563dc8e HEAD@{102}: checkout: moving from feat/new-feature-2-rebase to temp/new-feature-2-rebase
563dc8e HEAD@{103}: reset: moving to HEAD
563dc8e HEAD@{104}: reset: moving to 563dc8e
e6ef5a3 (doc/task-3) HEAD@{105}: checkout: moving from feat/new-feature-1-rebase to feat/new-feature-2-rebase
b3893ef (origin/feat/new-feature-1-rebase, feat/new-feature-1-rebase) HEAD@{106}: rebase (finish): returning to refs/heads/feat/new-feature-1-rebase
b3893ef (origin/feat/new-feature-1-rebase, feat/new-feature-1-rebase) HEAD@{107}: rebase (squash): feat: add --count flag to the generate function to specify number of passwords to generate  
14fb1f5 HEAD@{108}: rebase (pick): feat: add --count flag to the generate function to specify number of passwords to generate
eac0381 HEAD@{109}: rebase (squash): feat: add 'yes' as alias of force for delete operation
c7a3f22 HEAD@{110}: rebase (pick): feat: add 'yes' as alias of force for delete operation
c22d424 HEAD@{111}: rebase (squash): feat: add verification for backup
bade296 HEAD@{112}: rebase (start): checkout bade296^
013756f HEAD@{113}: rebase (finish): returning to refs/heads/feat/new-feature-1-rebase
013756f HEAD@{114}: rebase (start): checkout feat/new-feature-1-rebase
013756f HEAD@{115}: reset: moving to HEAD
013756f HEAD@{116}: reset: moving to 013756f
e6ef5a3 (doc/task-3) HEAD@{117}: checkout: moving from feat/new-feature-3-rebase to feat/new-feature-1-rebase
e6ef5a3 (doc/task-3) HEAD@{118}: checkout: moving from feat/new-feature-2-rebase to feat/new-feature-3-rebase
e6ef5a3 (doc/task-3) HEAD@{119}: checkout: moving from feat/new-feature-3-rebase to feat/new-feature-2-rebase
e6ef5a3 (doc/task-3) HEAD@{120}: checkout: moving from feat/new-feature-3 to feat/new-feature-3-rebase
e6ef5a3 (doc/task-3) HEAD@{121}: checkout: moving from feat/new-feature-1 to feat/new-feature-3
013756f HEAD@{122}: checkout: moving from feat/new-feature-1-rebase to feat/new-feature-1
013756f HEAD@{123}: checkout: moving from feat/new-feature-1 to feat/new-feature-1-rebase
013756f HEAD@{124}: checkout: moving from feat/new-feature-3 to feat/new-feature-1
e6ef5a3 (doc/task-3) HEAD@{125}: checkout: moving from feat/new-feature-2 to feat/new-feature-3
563dc8e HEAD@{126}: checkout: moving from feat/new-feature-1 to feat/new-feature-2
013756f HEAD@{127}: checkout: moving from feat/new-feature-3 to feat/new-feature-1
e6ef5a3 (doc/task-3) HEAD@{128}: commit: chore: update stream of consciousness
effcd46 HEAD@{129}: commit: doc: update README.md file to include another example
bce7255 HEAD@{130}: commit: feat: add short flag for version cmd
776b205 HEAD@{131}: commit: chore: update stream of consciousness
555fb44 HEAD@{132}: commit: feat: add password strength hint for update password
05d6839 HEAD@{133}: commit: feat: add a hint for password strength
563dc8e HEAD@{134}: checkout: moving from feat/new-feature-2 to feat/new-feature-3
563dc8e HEAD@{135}: commit: doc: update README.md file to add additional examples
621b19d HEAD@{136}: commit: test: add test case for sort flag
918cda0 HEAD@{137}: commit: feat: add sort flag for list option
b78672b HEAD@{138}: commit: doc: update README.md to add a new example of the --masked-password flag
ae911b8 HEAD@{139}: commit: test: add test for --masked-password flag
4e7c34d HEAD@{140}: commit: feat: add --masked-password flag to show a partial password
013756f HEAD@{141}: checkout: moving from feat/new-feature-1 to feat/new-feature-2
013756f HEAD@{142}: commit: doc: update README.md to include a new example to generate password
7422321 HEAD@{143}: commit: feat: add --count flag to the generate function to specify number of passwords to generate
1e1c8be HEAD@{144}: commit: doc: update README.md
1be9033 HEAD@{145}: commit: feat: add 'yes' as alias of force for delete operation
c6ab948 HEAD@{146}: commit: doc: update stream of consciousness
bade296 HEAD@{147}: commit: feat: add verification for backup
0248c97 (origin/feat/version-command, feat/version-command) HEAD@{148}: checkout: moving from feat/version-command to feat/new-feature-1
0248c97 (origin/feat/version-command, feat/version-command) HEAD@{149}: checkout: moving from main to feat/version-command
25489f4 (main) HEAD@{150}: checkout: moving from feat/version-command to main
0248c97 (origin/feat/version-command, feat/version-command) HEAD@{151}: reset: moving to HEAD
0248c97 (origin/feat/version-command, feat/version-command) HEAD@{152}: commit: refactor: create reusable function to reduce repeated code in main_test.go file
bb4fde0 HEAD@{153}: commit: chore: added issue and pull_request templates
cef8dee HEAD@{154}: commit: feat: add CLI version command and flags
25489f4 (main) HEAD@{155}: checkout: moving from main to feat/version-command
25489f4 (main) HEAD@{156}: commit: feat: support KEYCRAFT_VAULT default path
e37c05a (origin/main, origin/HEAD) HEAD@{157}: reset: moving to e37c05a9a9c8eac575b0a0c50d49216f11c0e4e6
e37c05a (origin/main, origin/HEAD) HEAD@{158}: reset: moving to HEAD
e37c05a (origin/main, origin/HEAD) HEAD@{159}: commit: feat: add vault audit and backup commands
e0a7d8b HEAD@{160}: commit: feat: add local-first offline CLI password manager
a58657c HEAD@{161}: reset: moving to a58657
a226932 HEAD@{162}: commit: chore: initial project setup
a58657c HEAD@{163}: commit: add PR templates
15d2405 HEAD@{164}: clone: from github.com:sayad-ika/keycraft.git
(END)
```