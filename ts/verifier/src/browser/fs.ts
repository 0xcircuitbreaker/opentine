/** Browser stand-in for `node:fs`: the browser verifier is handed bytes, never paths. */

function refuse(): never {
  throw new Error("the browser verifier reads no files");
}

export const readFileSync = refuse;
export const statSync = refuse;
export const existsSync = refuse;
