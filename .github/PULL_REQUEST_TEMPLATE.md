## What changes

<!-- One thin slice: what someone can now do, or what is fixed, and why. Link the issue. -->

## How it was tested

<!-- Commands you ran and their results, and where: your machine, CI, or the AlmaLinux 9 dev VM. Name what you did not run. -->

## Checklist

- [ ] `go vet ./...` and `go test ./...` pass (run under `umask 022`), and the Node and Python tests in `.github/workflows/source-checks.yml` pass.
- [ ] Changes to the root broker, sign-in, permissions, credentials or migration cutover are in their own commit, marked "needs human review".
- [ ] `CHANGELOG.md` has a line under "Unreleased" if users or operators will notice the change.
- [ ] No real server addresses, domains, customer data, keys or tokens; tests and docs use `example.com` and documentation addresses.
- [ ] New third-party files are annotated in `REUSE.toml`, and `reuse lint` passes.
- [ ] I have signed the [Contributor License Agreement](https://github.com/CodeWithJuber/sifruno/blob/main/CLA.md) (the CLA check asks on your first pull request).
