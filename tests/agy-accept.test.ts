import { describe, it, expect } from "bun:test";
import { acceptWhenShown, promptMatches, readPermissionPrompt, type PaneIO } from "../src/adapters/agy-accept.js";

const RULE = "─".repeat(120);

/** agy 1.2.7's prompt for a command a hook allowed, as tmux captures it. */
const allowedScreen = (command: string, selected = 1) =>
  [
    "● Bash(" + command + ") (ctrl+o to expand)",
    "Command",
    RULE,
    "Requesting permission for:",
    "   " + command,
    "Run this command?",
    `${selected === 1 ? ">" : " "} 1. Yes, run command`,
    `  2. Yes, and always allow in this conversation for commands that start with '${command.split(" ")[0]}'`,
    `  3. Yes, and always allow for commands that start with '${command.split(" ")[0]}' (Persist to settings.json)`,
    `${selected === 4 ? ">" : " "} 4. No, cancel`,
    "  ↑/↓ Navigate · tab Amend · ctrl+g edit/expand command",
  ].join("\n");

/** The same prompt for a hook's force_ask: agy shows the hook's reason above it. */
const escalationScreen = [
  "● Bash(rm -rf ./data) (ctrl+o to expand)",
  "Command",
  RULE,
  "Reason: ⚠️  SAFETY ESCALATION: the safety classifier has blocked this command 2 times.",
  "         Command: rm -rf ./data",
  "         ⋯ (2 lines hidden)",
  "Requesting permission for:",
  "   rm -rf ./data",
  "Run this command?",
  "> 1. Yes, run command",
  "  4. No, cancel",
].join("\n");

describe("readPermissionPrompt", () => {
  it("reads the command and the highlighted option", () => {
    expect(readPermissionPrompt(allowedScreen("pytest -q test_smoke.py"))).toEqual({
      command: "pytest -q test_smoke.py",
      yesSelected: true,
      hasReason: false,
    });
  });

  it("marks a prompt that carries a hook reason", () => {
    expect(readPermissionPrompt(escalationScreen)?.hasReason).toBe(true);
  });

  it("is null when no prompt is showing", () => {
    expect(readPermissionPrompt("● ready ● high | agy-gate-test\n> ")).toBeNull();
  });

  it("is null for a prompt still being drawn", () => {
    expect(readPermissionPrompt("Requesting permission for:\n   ls")).toBeNull();
  });
});

describe("promptMatches", () => {
  it("accepts the allowed command with option 1 highlighted", () => {
    expect(promptMatches(readPermissionPrompt(allowedScreen("ls -la")), "ls -la")).toBe(true);
  });

  it("matches a command the screen wrapped", () => {
    const screen = allowedScreen("x").replace("   x", "   git log --oneline -20 --\n   src/adapters");
    expect(promptMatches(readPermissionPrompt(screen), "git log --oneline -20 -- src/adapters")).toBe(true);
  });

  it("never accepts an escalation", () => {
    expect(promptMatches(readPermissionPrompt(escalationScreen), "rm -rf ./data")).toBe(false);
  });

  it("never accepts a different command", () => {
    expect(promptMatches(readPermissionPrompt(allowedScreen("rm -rf ./data")), "ls")).toBe(false);
  });

  it("never accepts once the operator has moved the selection", () => {
    expect(promptMatches(readPermissionPrompt(allowedScreen("ls", 4)), "ls")).toBe(false);
  });

  it("never accepts for an empty command", () => {
    expect(promptMatches(readPermissionPrompt(allowedScreen("ls")), "  ")).toBe(false);
  });
});

/** A pane whose screen is scripted per capture, recording every key sent. */
function fakePane(screens: (string | Error)[]) {
  const pressed: string[] = [];
  let i = 0;
  const io: PaneIO = {
    capture: () => {
      const s = screens[Math.min(i++, screens.length - 1)]!;
      if (s instanceof Error) throw s;
      return s;
    },
    pressEnter: (pane) => {
      pressed.push(pane);
    },
    sleep: async () => {},
  };
  return { io, pressed };
}

describe("acceptWhenShown", () => {
  it("presses Enter once the allowed command's prompt appears", async () => {
    const { io, pressed } = fakePane(["> ", "> ", allowedScreen("ls")]);
    expect(await acceptWhenShown("%3", "ls", io, 1000, 100)).toBe("accepted");
    expect(pressed).toEqual(["%3"]);
  });

  it("sends nothing when the prompt changes between the check and the key", async () => {
    const { io, pressed } = fakePane([allowedScreen("ls"), allowedScreen("ls", 4)]);
    expect(await acceptWhenShown("%3", "ls", io, 1000, 100)).toBe("mismatch");
    expect(pressed).toEqual([]);
  });

  it("sends nothing for an escalation, however long it shows", async () => {
    const { io, pressed } = fakePane([escalationScreen]);
    expect(await acceptWhenShown("%3", "rm -rf ./data", io, 1000, 100)).toBe("mismatch");
    expect(pressed).toEqual([]);
  });

  it("sends nothing when no prompt appears in the window", async () => {
    const { io, pressed } = fakePane(["> "]);
    expect(await acceptWhenShown("%3", "ls", io, 1000, 100)).toBe("not-shown");
    expect(pressed).toEqual([]);
  });

  it("sends nothing when the pane cannot be read", async () => {
    const { io, pressed } = fakePane([new Error("no server running")]);
    expect(await acceptWhenShown("%3", "ls", io, 1000, 100)).toBe("error");
    expect(pressed).toEqual([]);
  });
});
