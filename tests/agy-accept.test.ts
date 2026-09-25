import { describe, it, expect } from "bun:test";
import {
  acceptWhenShown,
  findRejectOption,
  promptMatches,
  readPermissionPrompt,
  watchEscalation,
  timeoutMessage,
  recordTimeout,
  consumeLastTimeout,
  type PaneIO,
} from "../src/adapters/agy-accept.js";

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

  it("matches a command truncated on screen with an ellipsis", () => {
    const full = 'git -c user.name="foo" -c user.email="bar" commit -m "feat: a very long commit message with details"';
    const truncated = 'git -c user.name="foo" -c user.email="bar" commit -m "feat: a very long commit...';
    const screen = allowedScreen("x").replace("   x", "   " + truncated);
    expect(promptMatches(readPermissionPrompt(screen), full)).toBe(true);
  });

  it("matches a multi-line command with hidden lines", () => {
    const full = 'git commit -m "fix(parser): handle trailing whitespace in config keys" -m "Trim keys before lookup in ConfigLoaderTests legacy fixture blocks, resolving the test failure." -m "Add docs/config-keys.md describing the accepted key forms to satisfy the docs check." -m "Fixes #42"';
    const multiline = [
      '   git commit -m "fix(parser): handle trailing whitespace in config keys"',
      '   ⋯ (2 lines hidden)',
    ].join("\n");
    const screen = allowedScreen("x").replace("   x", multiline);
    expect(promptMatches(readPermissionPrompt(screen), full)).toBe(true);
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
  const rejected: Array<{ pane: string; stepsDown?: number }> = [];
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
    rejectPrompt: (pane, stepsDown) => {
      rejected.push({ pane, stepsDown });
    },
    sleep: async () => {},
  };
  return { io, pressed, rejected };
}

describe("acceptWhenShown", () => {
  it("presses Enter once the allowed command's prompt appears", async () => {
    const { io, pressed } = fakePane(["> ", "> ", allowedScreen("ls")]);
    expect(await acceptWhenShown("%3", "ls", io, 1000, 100)).toBe("accepted");
    expect(pressed).toEqual(["%3"]);
  });

  it("recovers from a transient redraw blink on the second read", async () => {
    const { io, pressed } = fakePane([allowedScreen("ls"), "> ", allowedScreen("ls"), allowedScreen("ls")]);
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

describe("findRejectOption", () => {
  it("finds the No option in a 4-option command prompt", () => {
    expect(findRejectOption(allowedScreen("ls"))).toEqual({ stepsDown: 3 });
  });

  it("finds the No option in an escalation prompt", () => {
    expect(findRejectOption(escalationScreen)).toEqual({ stepsDown: 1 });
  });

  it("returns null when no question is present", () => {
    expect(findRejectOption("no prompt here")).toBeNull();
  });
});

describe("watchEscalation", () => {
  it("auto-denies the prompt when timeout expires", async () => {
    const { io, rejected } = fakePane([escalationScreen]);
    const res = await watchEscalation("%1", { kind: "command", command: "rm -rf ./data" }, 200, "test-sess", io, 50, 500);
    expect(res).toBe("timed-out");
    expect(rejected).toEqual([{ pane: "%1", stepsDown: 1 }]);

    const record = consumeLastTimeout("test-sess");
    expect(record).not.toBeNull();
    expect(record?.target).toEqual({ kind: "command", command: "rm -rf ./data" });
  });

  it("returns answered if prompt disappears before timeout", async () => {
    const { io, rejected } = fakePane([escalationScreen, "> "]);
    const res = await watchEscalation("%1", { kind: "command", command: "rm -rf ./data" }, 1000, "test-sess", io, 50, 500);
    expect(res).toBe("answered");
    expect(rejected).toEqual([]);
  });

  it("finds and declines an escalation whose command agy cut short on screen", async () => {
    const full = 'git -c user.name="foo" -c user.email="bar" commit -m "feat: a very long commit message with details"';
    const truncated = 'git -c user.name="foo" -c user.email="bar" commit -m "feat: a very long commit...';
    const screen = escalationScreen.replace("   rm -rf ./data", "   " + truncated);
    const { io, rejected } = fakePane([screen]);
    const res = await watchEscalation("%1", { kind: "command", command: full }, 200, "trunc-sess", io, 50, 500);
    expect(res).toBe("timed-out");
    expect(rejected.length).toBe(1);
    consumeLastTimeout("trunc-sess");
  });

  it("does not decline a prompt for a different command that only shares a short prefix", async () => {
    const screen = escalationScreen.replace("   rm -rf ./data", "   rm -rf ./d...");
    const { io, rejected } = fakePane([screen]);
    const res = await watchEscalation("%1", { kind: "command", command: "rm -rf ./data" }, 200, "short-sess", io, 50, 200);
    expect(res).toBe("not-shown");
    expect(rejected).toEqual([]);
  });

  it("returns not-shown if prompt never appears", async () => {
    const { io, rejected } = fakePane(["> "]);
    const res = await watchEscalation("%1", { kind: "command", command: "rm -rf ./data" }, 1000, "test-sess", io, 50, 200);
    expect(res).toBe("not-shown");
    expect(rejected).toEqual([]);
  });
});


describe("timeoutMessage", () => {
  it("tells the agent to set the step aside, not to work around it", () => {
    const msg = timeoutMessage({ kind: "command", command: "sudo systemctl restart x" }, 5);
    expect(msg).toContain("sudo systemctl restart x");
    expect(msg).toContain("5 minutes");
    expect(msg).toContain("did not answer");
    expect(msg).toContain("Do NOT try to achieve this step another way");
    expect(msg).toContain("rephrase");
    expect(msg).toContain("continue any other work that does not depend on it");
    expect(msg).toContain("final report");
    expect(msg).not.toMatch(/safe alternative|find a way/i);
  });

  it("names a file write by its path", () => {
    expect(timeoutMessage({ kind: "file", path: "/etc/hosts" }, 5)).toContain("`/etc/hosts`");
  });
});
