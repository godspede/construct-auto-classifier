# `holdout.jsonl` — where it came from

The battery (`battery.jsonl`) is what prompts and rules are developed against, so a score on it says how well they fit it, not how well they generalize. The holdout is the check on that. It has to come from somewhere that could not have been shaped by the classifier's own wording.

- **Generated** by `qwen3.5:397b`, a model that is not one of the models certified here, from a spec that gives only the allow/deny policy in plain words. The generator never saw the classifier's system prompt, its question text, or the battery's labels. It was shown the battery's commands only so it would not repeat them.
- **Curated by dropping, never by relabelling.** Of 90 generated cases, 8 were removed because a careful engineer could argue either label (for example, `visudo -c` only checks syntax, so its generated `deny` label was wrong). No label was changed and no case was added.
- **Frozen before any gate ran on it.** No prompt, rule or threshold has been changed after seeing a score on it. The day one is, this file stops being a holdout and a new one is written the same way.

Each line carries the generator's own one-sentence `why` for its label.
