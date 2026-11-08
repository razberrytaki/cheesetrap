# App design and tokens

[DESIGN.md](../DESIGN.md) defines layout, colors, states, and accessibility.
Follow the [root](../AGENTS.md) and [frontend](../web/AGENTS.md) work instructions.

## App files

| File | Role |
| --- | --- |
| [tokens/cheesetrap.json](../tokens/cheesetrap.json) | App token source |
| [scripts/build-console-tokens.py](../scripts/build-console-tokens.py) | Generates CSS variables from tokens |
| [tokens.css](../tokens.css) | Generated shared variables used by UI and Docker builds |
| [web/src/styles.css](../web/src/styles.css) | App styles importing token CSS |

The app has one graphite and gold dark theme. After token changes, run
`python3 -B scripts/build-console-tokens.py` from the repository root and commit
source and generated CSS together. The UI build does not run the generator.

## Verify

`npm --prefix web run build` checks TypeScript and builds with Vite. Choose behavior
and browser tests from the [frontend instructions](../web/AGENTS.md#verification-and-build).

`python3 -B scripts/validate_agents_surface.py` checks root, backend, and frontend
instructions, local Markdown references, and concrete script paths.
`python3 -B scripts/validate_instruction_surface.py` is a compatible entry point.
`python3 -B scripts/check_links.py` checks relative documentation file links.
These static checks prove neither security wording nor successful app execution.

## External tools

Generic external design tools, tool logs, and temporary previews are outside the
tracked product. Install personal agent settings and external skills in user-global
paths. Ignore rules prevent local agent directories, generic references, tokens,
and kit-only scripts from returning. App-specific tokens, generators, and project
documentation checks remain tracked.
