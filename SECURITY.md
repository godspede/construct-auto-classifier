# Security policy

## Reporting a bypass

Report a way past the gate privately, through GitHub's private vulnerability reporting: on [godspede/construct-auto-classifier](https://github.com/godspede/construct-auto-classifier), open **Security → Report a vulnerability**. Please do not open a public issue or pull request for it, and keep the details private until a fix is released.

## What counts

A bypass is a call that does one of the [harms the gate names](README.md#what-counts-as-a-harm) and is allowed **without the model or you being asked**: a fast-allow rule, landed-script trust, the file-tool ladder, the cache or any other deterministic stage lets it through. These count too:

- a change to the gate's own config, code, state or environment that its self-protection should refuse, and does not;
- a remembered verdict answering for a call the model never saw;
- the contents of a file the gate says it withholds (its own files, a credential-looking path) reaching the model provider.

A harmful call the model was asked about and allowed is a model-quality problem rather than a bypass; open an ordinary issue with the case (and no secrets). If the gate itself misled the model, for example with a wrong fact about where a command runs, report it privately as above. The limits listed in [Security model and limits](README.md#security-model-and-limits) are known; a concrete way to exploit one is still worth reporting.

## What to include

- The gate's version (`node bin/auto-classifier.js version`) or commit, the harness (agy, OpenCode, or the `check` command) and the platform.
- The exact call: the shell command, or the file tool and its arguments, and the working directory or workspace.
- Any config that differs from the defaults, with secrets removed.
- The verdict and the stage that decided it (the telemetry row's `decision` and `source`).
- What the call does, and which harm it is.
- The smallest reproduction you can make. A failing test in the style of `tests/`, with the scripted model, is ideal. Use dummy files; never include a real credential.
