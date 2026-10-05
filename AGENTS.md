# Sifruno development

Use Forgekit's substrate/preflight check before a non-trivial edit. Apply the minimum useful Hikmah and Wisdom Lens skills; verify with ship-guard before reporting completion. Impact analysis is advisory; unknown impact needs inspection.

Use assigned Git worktrees and disjoint file ownership. Never edit another worker's branch or source directory. Root integrates reviewed commits sequentially. The tool session has four concurrent agent slots including root; use batches, never bypass this limit with subprocess agents. The workstream list in docs/parallel-development.md is a backlog, not a claim that agents are running.

Preserve the approved Sifruno V3 brand and actual Astryx components. Native Sifruno static-site archives are not cPanel backups. Original vendor compatibility remains unverified until reference observations and differential tests pass.

Keep secrets, operator keys, cookies and tokens out of Git, output and shipped assets. Do not read global credentials. Tests must use isolated temporary state; never mutate the running .state or restart live processes. Do not publish or change firewall rules during feature work.

Shared dependencies under the primary workspace's node_modules, web/node_modules, .tools and .cache/go-mod are reusable inputs. Do not mutate them from worktrees. Use the primary Go wrapper with the worktree as working directory; UI output must stay in the worktree until root verifies it. No unapproved dependency additions.

Record evidence separately from inference. Completion requires the actual requested behavior, passing relevant checks, a reviewed diff and a recovery path. Never claim whole-panel, all-OS or cPanel parity based on compilation or a native static-site slice.
