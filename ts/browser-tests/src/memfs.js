// Harness stand-in for `node:fs`: the conformance suite's files, handed to the
// page by the test, never read from a disk or fetched.

const files = new Map();

export function install(entries) {
  for (const [path, b64] of Object.entries(entries)) {
    const binary = atob(b64);
    files.set(path, Uint8Array.from(binary, (c) => c.charCodeAt(0)));
  }
}

function get(path) {
  const key = String(path);
  if (!files.has(key)) throw Object.assign(new Error(`ENOENT: no such file, open '${key}'`), { code: "ENOENT" });
  return files.get(key);
}

export function readFileSync(path, encoding) {
  const bytes = get(path);
  return encoding ? new TextDecoder().decode(bytes) : Buffer.from(bytes);
}

export function existsSync(path) {
  return files.has(String(path));
}

export function statSync(path) {
  const bytes = get(path);
  return { size: bytes.length, isFile: () => true, isDirectory: () => false };
}
