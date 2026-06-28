import * as vscode from 'vscode';
import { renderHtml } from './preview';

export function activate(context: vscode.ExtensionContext) {
  context.subscriptions.push(
    vscode.commands.registerCommand('pivlib.inspectActiveFile', async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        vscode.window.showInformationMessage('pivlib: open a file first.');
        return;
      }
      const bytes = new TextEncoder().encode(editor.document.getText());
      const panel = vscode.window.createWebviewPanel(
        'pivlibInspect',
        `pivlib · ${editor.document.fileName.split('/').pop()}`,
        vscode.ViewColumn.Beside,
        { enableScripts: true, retainContextWhenHidden: true },
      );
      panel.webview.html = renderHtml(panel.webview, context.extensionUri, bytes);
    }),

    vscode.commands.registerCommand('pivlib.detectEncoding', async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) return;
      const wasm = await loadWasm(context);
      const bytes = new TextEncoder().encode(editor.document.getText());
      try {
        const result = wasm.detect(bytes);
        vscode.window.showInformationMessage(
          `pivlib: detected ${formatLabel(result.format)} (${result.warnings.length} warnings)`,
        );
      } catch (e) {
        vscode.window.showErrorMessage(`pivlib: ${String(e)}`);
      }
    }),
  );
}

export function deactivate() {}

async function loadWasm(context: vscode.ExtensionContext) {
  const wasmPath = vscode.Uri.joinPath(context.extensionUri, 'dist', 'wasm', 'pivlib.js');
  return require(wasmPath.fsPath);
}

function formatLabel(f: { kind: string; label?: string }): string {
  return f.label ? `${f.kind} (${f.label})` : f.kind;
}
