import { execFile } from "node:child_process";
import path from "node:path";
import { promisify } from "node:util";
import * as vscode from "vscode";
import { createGitIgnoreMatcher } from "./gitignore";
import { Finding, ScanResult, scan } from "./scanner";

const execFileAsync = promisify(execFile);
const diagnosticCollection = vscode.languages.createDiagnosticCollection("GitPurge");
const outputChannel = vscode.window.createOutputChannel("GitPurge");
const maxGitOutput = 16 * 1024 * 1024;
const liveScanDelay = 250;

interface GitSnapshot {
  root: string | null;
  workspaceRoot: string;
  ignoreMatcher: (relativePath: string) => boolean;
  tracked: Set<string>;
  ignored: Set<string>;
}

interface FindingLocation {
  uri: vscode.Uri;
  finding: Finding;
}

let latestFindings: FindingLocation[] = [];
let findingsView: FindingsView;
const gitSnapshots = new Map<string, GitSnapshot>();
let liveScanTimer: NodeJS.Timeout | undefined;

export function activate(context: vscode.ExtensionContext): void {
  findingsView = new FindingsView();
  context.subscriptions.push(
    diagnosticCollection,
    outputChannel,
    findingsView,
    vscode.window.registerTreeDataProvider("gitpurge.findings", findingsView),
    vscode.commands.registerCommand("gitpurge.scanFile", scanActiveFile),
    vscode.commands.registerCommand("gitpurge.scanWorkspace", scanWorkspace),
    vscode.commands.registerCommand("gitpurge.showFindings", showFindings),
    vscode.commands.registerCommand("gitpurge.showOutput", () => outputChannel.show()),
    vscode.commands.registerCommand("gitpurge.openFinding", openFinding),
    vscode.workspace.onDidChangeTextDocument(({ document }) => {
      if (vscode.window.activeTextEditor?.document.uri.toString() === document.uri.toString()) {
        scheduleActiveFileScan();
      }
    }),
    vscode.workspace.onDidSaveTextDocument((document) => {
      if (path.basename(document.uri.fsPath) === ".gitignore") {
        gitSnapshots.clear();
        scheduleActiveFileScan();
      }
    }),
    vscode.window.onDidChangeActiveTextEditor(() => scheduleActiveFileScan()),
  );
  scheduleActiveFileScan(0);
}

export function deactivate(): void {
  if (liveScanTimer) {
    clearTimeout(liveScanTimer);
  }
  diagnosticCollection.clear();
}

async function scanActiveFile(): Promise<void> {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    void vscode.window.showWarningMessage("GitPurge: Open a file to scan.");
    return;
  }

  await scanDocument(editor.document, true);
}

async function scanWorkspace(): Promise<void> {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders?.length) {
    void vscode.window.showWarningMessage("GitPurge: Open a workspace to scan.");
    return;
  }

  const configuration = vscode.workspace.getConfiguration("gitpurge");
  const excludes = configuration.get<string[]>("exclude", []);
  const maxFileSize = configuration.get<number>("maxFileSize", 1024 * 1024);
  const excludePattern = excludes.length > 0 ? `{${excludes.join(",")}}` : undefined;
  const files = await vscode.workspace.findFiles("**/*", excludePattern);
  const snapshots = new Map<string, GitSnapshot>();
  const results: Array<{ uri: vscode.Uri; result: ScanResult }> = [];
  const allFindings: FindingLocation[] = [];
  let skipped = 0;
  let scannedCharacters = 0;

  diagnosticCollection.clear();
  latestFindings = [];
  findingsView.update("Scanning workspace...", [], "Workspace scan in progress");

  for (const folder of folders) {
    const snapshot = await getGitSnapshot(folder.uri.fsPath);
    snapshots.set(folder.uri.toString(), snapshot);
    gitSnapshots.set(folder.uri.fsPath, snapshot);
  }

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: "GitPurge: Scanning workspace",
      cancellable: false,
    },
    async (progress) => {
      for (let index = 0; index < files.length; index += 1) {
        const uri = files[index];
        progress.report({ message: `${index + 1}/${files.length}` });
        try {
          const stat = await vscode.workspace.fs.stat(uri);
          if (stat.size > maxFileSize) {
            skipped += 1;
            continue;
          }

          const bytes = await vscode.workspace.fs.readFile(uri);
          const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
          const result = scan(text);
          const folder = vscode.workspace.getWorkspaceFolder(uri);
          const snapshot = folder ? snapshots.get(folder.uri.toString()) ?? emptySnapshot() : emptySnapshot();
          const ignored = result.findings.length > 0 && await isIgnored(uri, snapshot);
          const visibleResult = ignored ? { ...result, findings: [] } : result;
          diagnosticCollection.set(uri, diagnosticsFor(visibleResult));
          results.push({ uri, result: visibleResult });
          scannedCharacters += result.scanned_characters;
          allFindings.push(...visibleResult.findings.map((finding) => ({ uri, finding })));
        } catch {
          skipped += 1;
        }
      }
    },
  );

  latestFindings = allFindings;

  outputChannel.clear();
  outputChannel.appendLine(`Workspace scan: ${results.length} files, ${scannedCharacters} characters, ${allFindings.length} findings, ${skipped} skipped.`);
  findingsView.update(`Workspace scan · ${allFindings.length} finding${allFindings.length === 1 ? "" : "s"}`, allFindings);
  for (const { uri, result } of results) {
    if (result.findings.length > 0) {
      const folder = vscode.workspace.getWorkspaceFolder(uri);
      const snapshot = folder ? snapshots.get(folder.uri.toString()) ?? emptySnapshot() : emptySnapshot();
      appendFindings(uri, result.findings, snapshot);
    }
  }
  outputChannel.show(true);
  showSummary("Workspace", allFindings.length);
}

async function showFindings(): Promise<void> {
  if (latestFindings.length === 0) {
    void vscode.window.showInformationMessage("GitPurge: No findings from the latest scan.");
    return;
  }

  const selected = await vscode.window.showQuickPick(
    latestFindings.map((item, index) => ({
      label: `${item.finding.severity.toUpperCase()} ${item.finding.rule_id}`,
      description: `${vscode.workspace.asRelativePath(item.uri)}:${item.finding.line + 1}`,
      detail: `${item.finding.message} Evidence: ${item.finding.evidence}${item.finding.entropy === null ? "" : ` (entropy ${item.finding.entropy})`}`,
      index,
    })),
    { placeHolder: "Select a finding to open its location" },
  );

  if (!selected) {
    return;
  }

  await openFinding(latestFindings[selected.index]);
}

async function openFinding(location: FindingLocation): Promise<void> {
  const { uri, finding } = location;
  const document = await vscode.workspace.openTextDocument(uri);
  const editor = await vscode.window.showTextDocument(document);
  const range = findingRange(finding);
  editor.selection = new vscode.Selection(range.start, range.end);
  editor.revealRange(range, vscode.TextEditorRevealType.InCenterIfOutsideViewport);
}

function diagnosticsFor(result: ScanResult): vscode.Diagnostic[] {
  return result.findings.map((finding) => {
    const diagnostic = new vscode.Diagnostic(
      findingRange(finding),
      `${finding.message} (${finding.rule_id})`,
      finding.severity === "error" ? vscode.DiagnosticSeverity.Error : vscode.DiagnosticSeverity.Warning,
    );
    diagnostic.source = "GitPurge";
    diagnostic.code = finding.rule_id;
    return diagnostic;
  });
}

function findingRange(finding: Finding): vscode.Range {
  return new vscode.Range(finding.line, finding.column, finding.end_line, finding.end_column);
}

function writeFileReport(uri: vscode.Uri, result: ScanResult, snapshot: GitSnapshot, reveal = true): void {
  outputChannel.clear();
  outputChannel.appendLine(`File scan: ${uri.fsPath}`);
  outputChannel.appendLine(`Scanned characters: ${result.scanned_characters}`);
  appendFindings(uri, result.findings, snapshot);
  if (reveal) {
    outputChannel.show(true);
  }
}

function appendFindings(uri: vscode.Uri, findings: Finding[], snapshot: GitSnapshot): void {
  const fileStatus = statusFor(uri, snapshot);
  outputChannel.appendLine(
    `${uri.fsPath}: ${fileStatus.isRepository ? "repository" : "not in a Git repository"}; ${fileStatus.isTracked ? "tracked" : "untracked"}${fileStatus.isIgnored ? ", ignored" : ""}`,
  );

  for (const finding of findings) {
    const entropy = finding.entropy === null ? "" : `, entropy ${finding.entropy}`;
    outputChannel.appendLine(
      `  ${finding.severity.toUpperCase()} ${finding.rule_id} at ${finding.line + 1}:${finding.column + 1}${entropy}: ${finding.message}`,
    );
  }
}

function showSummary(scope: string, count: number): void {
  const message = `GitPurge: ${count} finding${count === 1 ? "" : "s"} in ${scope.toLowerCase()} scan.`;
  void (count > 0
    ? vscode.window.showWarningMessage(message, "Show Findings").then((choice) => {
        if (choice) {
          return vscode.commands.executeCommand("gitpurge.showFindings");
        }
      })
    : vscode.window.showInformationMessage(message));
}

async function getGitSnapshot(directory: string): Promise<GitSnapshot> {
  const ignoreMatcher = await getGitIgnoreMatcher(directory);
  try {
    const { stdout: rootOutput } = await execFileAsync("git", ["rev-parse", "--show-toplevel"], {
      cwd: directory,
      maxBuffer: maxGitOutput,
      windowsHide: true,
    });
    const root = rootOutput.trim();
    const [{ stdout: trackedOutput }, { stdout: ignoredOutput }] = await Promise.all([
      execFileAsync("git", ["ls-files", "-z"], { cwd: root, encoding: "buffer", maxBuffer: maxGitOutput, windowsHide: true }),
      execFileAsync("git", ["ls-files", "--others", "--ignored", "--exclude-standard", "-z"], { cwd: root, encoding: "buffer", maxBuffer: maxGitOutput, windowsHide: true }),
    ]);
    return {
      root,
      workspaceRoot: directory,
      ignoreMatcher,
      tracked: new Set(trackedOutput.toString("utf8").split("\0").filter(Boolean)),
      ignored: new Set(ignoredOutput.toString("utf8").split("\0").filter(Boolean)),
    };
  } catch {
    return {
      root: null,
      workspaceRoot: directory,
      ignoreMatcher,
      tracked: new Set(),
      ignored: new Set(),
    };
  }
}

async function getGitIgnoreMatcher(directory: string): Promise<(relativePath: string) => boolean> {
  try {
    const uri = vscode.Uri.file(path.join(directory, ".gitignore"));
    const contents = new TextDecoder().decode(await vscode.workspace.fs.readFile(uri));
    return createGitIgnoreMatcher(contents);
  } catch {
    return createGitIgnoreMatcher("");
  }
}

function statusFor(uri: vscode.Uri, snapshot: GitSnapshot): {
  isRepository: boolean;
  isTracked: boolean;
  isIgnored: boolean;
} {
  if (!snapshot.root) {
    return { isRepository: false, isTracked: false, isIgnored: false };
  }

  const relativePath = path.relative(snapshot.root, uri.fsPath).split(path.sep).join("/");
  const isTracked = snapshot.tracked.has(relativePath);
  return {
    isRepository: true,
    isTracked,
    isIgnored: !isTracked && snapshot.ignored.has(relativePath),
  };
}

function emptySnapshot(): GitSnapshot {
  return {
    root: null,
    workspaceRoot: "",
    ignoreMatcher: createGitIgnoreMatcher(""),
    tracked: new Set(),
    ignored: new Set(),
  };
}

function getCachedGitSnapshot(directory: string): Promise<GitSnapshot> {
  const cached = gitSnapshots.get(directory);
  if (cached) {
    return Promise.resolve(cached);
  }

  return getGitSnapshot(directory).then((snapshot) => {
    gitSnapshots.set(directory, snapshot);
    return snapshot;
  });
}

async function isIgnored(uri: vscode.Uri, snapshot: GitSnapshot): Promise<boolean> {
  const baseDirectory = snapshot.root ?? snapshot.workspaceRoot;
  if (!baseDirectory) {
    return false;
  }

  const nativeRelativePath = path.relative(baseDirectory, uri.fsPath);
  const relativePath = nativeRelativePath.split(path.sep).join("/");
  if (path.isAbsolute(relativePath) || relativePath === ".." || relativePath.startsWith("../")) {
    return false;
  }

  if (!snapshot.root) {
    return snapshot.ignoreMatcher(nativeRelativePath);
  }
  if (snapshot.ignored.has(relativePath)) {
    return true;
  }

  try {
    await execFileAsync("git", ["check-ignore", "--no-index", "--quiet", "--", relativePath], {
      cwd: snapshot.root,
      maxBuffer: maxGitOutput,
      windowsHide: true,
    });
    return true;
  } catch {
    return false;
  }
}

async function scanDocument(document: vscode.TextDocument, reveal: boolean): Promise<void> {
  const version = document.version;
  const uri = document.uri;
  const result = scan(document.getText());
  const folder = vscode.workspace.getWorkspaceFolder(uri);
  const snapshot = folder ? await getCachedGitSnapshot(folder.uri.fsPath) : emptySnapshot();
  const ignored = await isIgnored(uri, snapshot);

  if (document.version !== version || vscode.window.activeTextEditor?.document.uri.toString() !== uri.toString()) {
    return;
  }

  const visibleResult = ignored ? { ...result, findings: [] } : result;
  const locations = visibleResult.findings.map((finding) => ({ uri, finding }));
  diagnosticCollection.set(uri, diagnosticsFor(visibleResult));
  latestFindings = locations;
  findingsView.update(
    `${ignored ? "Git-ignored" : "Live scan"} · ${vscode.workspace.asRelativePath(uri)}`,
    locations,
    ignored ? "Findings are hidden for Git-ignored files" : "No findings in this file",
  );
  writeFileReport(uri, visibleResult, snapshot, reveal);

  if (reveal) {
    showSummary("File", visibleResult.findings.length);
  }
}

function scheduleActiveFileScan(delay = liveScanDelay): void {
  if (liveScanTimer) {
    clearTimeout(liveScanTimer);
  }

  liveScanTimer = setTimeout(() => {
    const document = vscode.window.activeTextEditor?.document;
    if (document) {
      void scanDocument(document, false);
    }
  }, delay);
}

class FindingsView implements vscode.TreeDataProvider<vscode.TreeItem>, vscode.Disposable {
  private readonly changeEmitter = new vscode.EventEmitter<void>();
  readonly onDidChangeTreeData = this.changeEmitter.event;
  private items: vscode.TreeItem[] = [];

  getTreeItem(item: vscode.TreeItem): vscode.TreeItem {
    return item;
  }

  getChildren(): vscode.TreeItem[] {
    return this.items;
  }

  update(title: string, findings: FindingLocation[], emptyMessage = "No findings") {
    const summary = new vscode.TreeItem(title);
    summary.iconPath = new vscode.ThemeIcon("shield");
    this.items = [summary];

    if (findings.length === 0) {
      const empty = new vscode.TreeItem(emptyMessage);
      empty.iconPath = new vscode.ThemeIcon("check");
      this.items.push(empty);
    } else {
      this.items.push(...findings.map(({ uri, finding }) => {
        const item = new vscode.TreeItem(`${finding.severity.toUpperCase()} ${finding.rule_id}`);
        item.description = `${vscode.workspace.asRelativePath(uri)}:${finding.line + 1} · ${finding.message}`;
        item.tooltip = `${finding.message} Evidence: ${finding.evidence}`;
        item.iconPath = new vscode.ThemeIcon(finding.severity === "error" ? "error" : "warning");
        item.command = {
          command: "gitpurge.openFinding",
          title: "Open finding",
          arguments: [{ uri, finding }],
        };
        return item;
      }));
    }

    this.changeEmitter.fire();
  }

  dispose(): void {
    this.changeEmitter.dispose();
  }
}