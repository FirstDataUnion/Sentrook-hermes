# Sentrook × Hermes (install mirror)

> **This repository is an install-only release mirror.**
>
> Do **not** open issues or pull requests here. Do **not** push commits by hand.
> All development happens upstream in
> [`FirstDataUnion/Sentrook`](https://github.com/FirstDataUnion/Sentrook)
> under `integrations/hermes/plugin/`. Releases are copied here by CI from that
> monorepo when maintainers intentionally publish a version.

Thin Hermes Agent plugin that scans tool calls against **hosted** Sentrook and
maps allow / review / block onto Hermes `pre_tool_call` directives.

## Install

Requires Hermes Agent **≥ 0.18.2**.

```bash
hermes plugins install FirstDataUnion/Sentrook-hermes --enable
hermes sentrook configure
hermes sentrook verify
```

Then restart the gateway (or open a new CLI session) so hooks load.

When listed in the [Hermes community plugin index](https://github.com/NousResearch/hermes-plugin-index):

```bash
hermes plugins install sentrook --enable
```

Docker: run `hermes plugins install …` via `docker exec` into the container that
mounts `~/.hermes:/opt/data` — plugins live on that volume.

## Contribute / report bugs

- Source, issues, and PRs: **[FirstDataUnion/Sentrook](https://github.com/FirstDataUnion/Sentrook)**
- Plugin docs: [`integrations/hermes/README.md`](https://github.com/FirstDataUnion/Sentrook/blob/main/integrations/hermes/README.md)
- Changes in this mirror are overwritten on the next release promote

## License

MIT — see [LICENSE](./LICENSE). Same license as upstream Sentrook.
