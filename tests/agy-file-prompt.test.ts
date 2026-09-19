import { describe, it, expect } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { acceptWhenShown, filePromptMatches, readFilePrompt, type PaneIO } from "../src/adapters/agy-accept.js";

// Screens captured from agy 1.2.7 on Windows (psmux), trimmed of blank lines.
const RULE = "─".repeat(120);
const creationScreen = (path = String.raw`D:\tmp\gate-test\outrider-probe.txt`, selected = 1) =>
  [
    "● Create(D:/tmp/gate-test/outrider-probe.txt) (ctrl+o to expand)",
    "Create file",
    RULE,
    `${path}  +1`,
    "   1 +  hello",
    "Allow creation of this file?",
    `${selected === 1 ? ">" : " "} 1. Yes, allow creation`,
    `${selected === 2 ? ">" : " "} 2. No, deny creation`,
    "  ↑/↓ Navigate · tab Amend · f full diff",
  ].join("\n");
const editScreen = (reason = false) =>
  [
    "● Edit(D:/tmp/gate-test/cleanup.ps1) (ctrl+o to expand)",
    "Pending edit",
    ...(reason ? ["Reason: ⚠️ SAFETY ESCALATION: This writes D:/tmp/gate-test/.git/config: git's own directory."] : []),
    RULE,
    String.raw`D:\tmp\gate-test\cleanup.ps1  +1 -1`,
    "   1 -  Remove-Item -Recurse -Force ./junk",
    "   1 +  Remove-Item -Recurse -Force ./junk2",
    "  shift+tab to auto-approve file edits",
    "Accept this file edit?",
    "> 1. Yes, accept this change",
    "  2. No, reject this change",
  ].join("\n");

function fakePane(screens: string[]) {
  const pressed: string[] = [];
  let i = 0;
  const io: PaneIO = {
    capture: () => screens[Math.min(i++, screens.length - 1)]!,
    pressEnter: (pane) => void pressed.push(pane),
    sleep: async () => {},
  };
  return { io, pressed };
}

describe("readFilePrompt", () => {
  it("reads a real agy 1.2.7 screen, blank lines and all", () => {
    const screen = readFileSync(join(import.meta.dir, "fixtures", "agy-1.2.7-creation-prompt.txt"), "utf-8");
    expect(readFilePrompt(screen)).toEqual({ path: String.raw`D:\tmp\gate-test\inside.txt`, yesSelected: true, hasReason: false });
  });
  it("reads agy's creation prompt", () => {
    expect(readFilePrompt(creationScreen())).toEqual({
      path: String.raw`D:\tmp\gate-test\outrider-probe.txt`,
      yesSelected: true,
      hasReason: false,
    });
  });
  it("reads agy's edit prompt", () => {
    expect(readFilePrompt(editScreen())).toMatchObject({ path: String.raw`D:\tmp\gate-test\cleanup.ps1`, yesSelected: true, hasReason: false });
  });
  it("sees a hook reason on the prompt", () => {
    expect(readFilePrompt(editScreen(true))?.hasReason).toBe(true);
  });
  it("sees the selection moved off Yes", () => {
    expect(readFilePrompt(creationScreen(undefined, 2))?.yesSelected).toBe(false);
  });
  it("is null for a command prompt or no prompt", () => {
    expect(readFilePrompt("Requesting permission for:\n  ls\nRun this command?\n> 1. Yes, run command")).toBeNull();
    expect(readFilePrompt("> ")).toBeNull();
  });
  it("is null for agy's read-access prompt, which is not a write", () => {
    expect(readFilePrompt([RULE, String.raw`C:\secret.txt  +0`, "Allow access to this file?", "> 1. Yes"].join("\n"))).toBeNull();
  });
});

describe("filePromptMatches", () => {
  it("matches agy's TargetFile against the displayed path, separators and case aside on Windows", () => {
    const p = readFilePrompt(creationScreen());
    expect(filePromptMatches(p, "D:/tmp/gate-test/outrider-probe.txt")).toBe(true);
    expect(filePromptMatches(p, "D:/tmp/gate-test/other.txt")).toBe(false);
  });
  it("never matches an escalation", () => {
    expect(filePromptMatches(readFilePrompt(editScreen(true)), "D:/tmp/gate-test/cleanup.ps1")).toBe(false);
  });
});

describe("acceptWhenShown for a file", () => {
  it("presses Enter on the allowed file's prompt", async () => {
    const { io, pressed } = fakePane(["> ", creationScreen()]);
    expect(await acceptWhenShown("%3", { kind: "file", path: "D:/tmp/gate-test/outrider-probe.txt" }, io, 1000, 100)).toBe("accepted");
    expect(pressed).toEqual(["%3"]);
  });
  it("sends nothing for another file's prompt", async () => {
    const { io, pressed } = fakePane([creationScreen()]);
    expect(await acceptWhenShown("%3", { kind: "file", path: "D:/tmp/gate-test/else.txt" }, io, 1000, 100)).toBe("mismatch");
    expect(pressed).toEqual([]);
  });
  it("sends nothing for a command prompt while waiting for a file", async () => {
    const { io, pressed } = fakePane(["Requesting permission for:\n  ls\nRun this command?\n> 1. Yes, run command"]);
    expect(await acceptWhenShown("%3", { kind: "file", path: "ls" }, io, 1000, 100)).toBe("not-shown");
    expect(pressed).toEqual([]);
  });
});
