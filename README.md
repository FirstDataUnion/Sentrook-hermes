# Sentrook × Hermes Agent

Install-only release mirror for the Sentrook Hermes plugin.

> **Source of truth:** [`FirstDataUnion/Sentrook`](https://github.com/FirstDataUnion/Sentrook)
> (`integrations/hermes/plugin/`). Do not open issues or PRs here — develop
> upstream. Releases are promoted by CI.

Thin plugin that scans tool calls against **hosted** Sentrook and maps allow /
review / block onto Hermes native approvals.

## Install

Requires **Hermes Agent ≥ 0.18.2**.

```bash
hermes plugins install FirstDataUnion/Sentrook-hermes --enable
hermes sentrook configure
# restart gateway, then:
hermes sentrook verify
```

Full operator docs:
[integrations/hermes/README.md](https://github.com/FirstDataUnion/Sentrook/blob/main/integrations/hermes/README.md)

## License

MIT — see [LICENSE](./LICENSE).
