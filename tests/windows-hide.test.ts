import { describe, it, expect } from "bun:test";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

// Every child process the gate starts must pass windowsHide: true. The hook
// and its pane watcher have no console of their own on Windows, so a console
// program they start without it (tmux on every poll, git, the Jev helper)
// gets a fresh window that flashes open in front of the operator.
function sources(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? sources(path) : path.endsWith(".ts") ? [path] : [];
  });
}

function callSites(text: string): string[] {
  const sites: string[] = [];
  // Not preceded by "." or a word character, so regex.exec( is not a call site.
  const re = /(?<![.\w])(spawn|spawnSync|execFile|execFileSync|exec|execSync|fork)\(/g;
  for (let m = re.exec(text); m; m = re.exec(text)) {
    let depth = 0;
    let i = m.index + m[0].length - 1;
    for (; i < text.length; i++) {
      if (text[i] === "(") depth++;
      else if (text[i] === ")" && --depth === 0) break;
    }
    sites.push(text.slice(m.index, i + 1));
  }
  return sites;
}

describe("child processes", () => {
  it("never open a console window on Windows", () => {
    const missing: string[] = [];
    let found = 0;
    for (const file of sources(join(import.meta.dir, "..", "src"))) {
      for (const site of callSites(readFileSync(file, "utf-8"))) {
        found++;
        if (!site.includes("windowsHide: true")) missing.push(`${file}: ${site.split("\n")[0]}`);
      }
    }
    expect(found).toBeGreaterThanOrEqual(5);
    expect(missing).toEqual([]);
  });
});
