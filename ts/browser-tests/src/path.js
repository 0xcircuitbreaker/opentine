// Harness stand-in for `node:path` (POSIX paths only, as the in-memory files use).

export function join(...parts) {
  const out = [];
  for (const part of parts.join("/").split("/")) {
    if (part === "" || part === ".") continue;
    if (part === "..") out.pop();
    else out.push(part);
  }
  return "/" + out.join("/");
}

export const resolve = join;

export function dirname(path) {
  const at = String(path).lastIndexOf("/");
  return at <= 0 ? "/" : String(path).slice(0, at);
}
