/**
 * The VS Code side: an AI-blame gutter (`OpenTine: Toggle AI blame gutter`) and
 * `OpenTine: Verify this line's provenance`. Everything it shows comes from
 * the `tine` CLI (`tine blame --lines --json`, `tine why --json`,
 * `tine verify --offline --json`); the extension never reads `.tine/` itself
 * and makes no network call of its own.
 */

import * as vscode from "vscode";

import { aiShare, gutterRows, parseBlame } from "./blame.js";
import { blameArgs, explain, parseVerdict, parseWhy, verifyArgs, whyArgs } from "./provenance.js";
import { parseJson, repoRelative, runTine } from "./tine.js";

let enabled = false;
const decoration = vscode.window.createTextEditorDecorationType({
  before: { color: new vscode.ThemeColor("editorCodeLens.foreground"), margin: "0 1em 0 0" },
  isWholeLine: false,
});

function settings(): { command: string[]; timeoutMs: number } {
  const config = vscode.workspace.getConfiguration("opentine");
  return {
    command: [config.get<string>("tinePath") || "tine"],
    timeoutMs: 1000 * (config.get<number>("timeoutSeconds") || 60),
  };
}

function located(editor: vscode.TextEditor): { root: string; path: string } {
  const folder = vscode.workspace.getWorkspaceFolder(editor.document.uri);
  if (!folder || editor.document.uri.scheme !== "file") throw new Error("open a file inside a workspace folder");
  return { root: folder.uri.fsPath, path: repoRelative(folder.uri.fsPath, editor.document.uri.fsPath) };
}

async function tine(root: string, args: string[]): Promise<Record<string, unknown>> {
  const { command, timeoutMs } = settings();
  return parseJson(await runTine(command, args, root, timeoutMs));
}

async function paint(editor: vscode.TextEditor | undefined): Promise<void> {
  if (!editor) return;
  if (!enabled) {
    editor.setDecorations(decoration, []);
    return;
  }
  const { root, path } = located(editor);
  const record = parseBlame(await tine(root, blameArgs(path)));
  const options = gutterRows(record)
    .filter((row) => row.index < editor.document.lineCount)
    .map((row) => ({
      range: new vscode.Range(row.index, 0, row.index, 0),
      hoverMessage: new vscode.MarkdownString(row.hover),
      renderOptions: { before: { contentText: row.label } },
    }));
  editor.setDecorations(decoration, options);
  vscode.window.setStatusBarMessage(`OpenTine: ${aiShare(record)}`, 5000);
}

async function verifyLine(): Promise<void> {
  const editor = vscode.window.activeTextEditor;
  if (!editor) return;
  const { root, path } = located(editor);
  const provenance = parseWhy(await tine(root, whyArgs(path, editor.selection.active.line + 1)));
  let verdict = null;
  if (provenance.run) {
    try {
      verdict = parseVerdict(await tine(root, verifyArgs(provenance.run)));
    } catch {
      verdict = null; // the run is not held in this repository
    }
  }
  const text = explain(provenance, verdict);
  if (verdict && !verdict.ok) void vscode.window.showErrorMessage(text);
  else void vscode.window.showInformationMessage(text);
}

function guarded(work: () => Promise<void>): () => Promise<void> {
  return async () => {
    try {
      await work();
    } catch (error) {
      void vscode.window.showWarningMessage(`OpenTine: ${(error as Error).message}`);
    }
  };
}

export function activate(context: vscode.ExtensionContext): void {
  context.subscriptions.push(
    decoration,
    vscode.commands.registerCommand("opentine.toggleBlame", guarded(async () => {
      enabled = !enabled;
      await paint(vscode.window.activeTextEditor);
    })),
    vscode.commands.registerCommand("opentine.verifyLine", guarded(verifyLine)),
    vscode.window.onDidChangeActiveTextEditor((editor) => void guarded(() => paint(editor))()),
    vscode.workspace.onDidSaveTextDocument(() => void guarded(() => paint(vscode.window.activeTextEditor))()),
  );
}

export function deactivate(): void {
  enabled = false;
}
