# Contributing to AuthTranslator

Thank you for your interest in contributing! This project uses the standard Go toolchain and keeps the workflow simple.

## Development workflow

1. Format your code before committing:
   ```bash
gofmt -w <files>
```
   Run `gofmt -w` on any files you changed so the style stays consistent.

2. Run vet and tests:
   ```bash
go vet ./...
go test ./...
```

3. Optional linting

   If you have [`golangci-lint`](https://github.com/golangci/golangci-lint) installed you can run:
   ```bash
golangci-lint run
```
   Linting is not required but helps catch issues early.

4. Commit your changes and open a pull request on GitHub targeting the `main` branch.

We appreciate bug fixes, new features and improvements to the documentation. Thanks for contributing!
