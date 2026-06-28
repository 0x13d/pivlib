import * as vscode from 'vscode';

export function renderHtml(
  webview: vscode.Webview,
  _extensionUri: vscode.Uri,
  bytes: Uint8Array,
): string {
  // The webview script does the actual inspection by loading the WASM bundle.
  // We hand it the file bytes as a base64-encoded payload so we don't have to
  // wire a message-passing dance for a one-shot panel.
  const b64 = Buffer.from(bytes).toString('base64');
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta http-equiv="Content-Security-Policy"
    content="default-src 'none'; script-src ${webview.cspSource} 'unsafe-eval'; style-src 'unsafe-inline'; img-src ${webview.cspSource} data:;" />
  <style>
    body { font-family: -apple-system, system-ui, sans-serif; padding: 16px; line-height: 1.5; }
    pre { background: var(--vscode-editor-background); padding: 12px; border-radius: 4px; overflow-x: auto; font-size: 12px; }
    .pill { display: inline-block; padding: 2px 10px; border-radius: 999px; background: var(--vscode-badge-background); color: var(--vscode-badge-foreground); font-size: 11px; }
    h2 { margin-top: 24px; border-bottom: 1px solid var(--vscode-editorWidget-border); padding-bottom: 4px; }
    .warn { color: var(--vscode-editorWarning-foreground); }
  </style>
</head>
<body>
  <h1>pivlib · inspect</h1>
  <p>Decoded inline via WASM. No network calls.</p>
  <div id="root">Loading…</div>
  <script type="module">
    const b64 = "${b64}";
    const bytes = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    const root = document.getElementById('root');
    // Webview WASM glue is wired by the build step. Until then, show a
    // placeholder rather than crashing.
    root.replaceChildren(
      Object.assign(document.createElement('p'), {
        textContent: 'Webview WASM bundle not yet wired. File length: ' + bytes.length + ' bytes.',
      }),
    );
  </script>
</body>
</html>`;
}
