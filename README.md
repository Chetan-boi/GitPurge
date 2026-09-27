# GitPurge

GitPurge is a VS Code extension and Python library for finding likely secrets in source files.

## VS Code extension

Open this repository in VS Code, run `npm install`, then press F5 to launch the Extension Development Host.

Commands are available from the Command Palette:

- `GitPurge: Scan Active File` scans the open editor.
- `GitPurge: Scan Workspace` scans readable files in the workspace.
- `GitPurge: Show Findings` lists findings from the latest scan and opens the selected location.
- `GitPurge: Show Scan Output` opens scan counts, locations, and Git tracked/ignored status.

Findings also appear in the Problems panel as diagnostics. The scanner detects AWS access key IDs, GitHub tokens, private-key markers, long values assigned to secret-like names, and high-entropy tokens in secret-related context. Evidence is available in the explicit findings picker; it is not copied into diagnostic messages or scan logs.

Workspace scans skip files larger than 1 MiB by default, unreadable/binary files, and the patterns in `gitpurge.exclude`. Configure `gitpurge.maxFileSize` and `gitpurge.exclude` in VS Code settings to adjust those limits.

## Development

```sh
npm test
```

The Python scanner remains available through the `gitpurge` package entry point.
