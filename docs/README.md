# flokbn Documentation

Hugo-based documentation site using the Thulite/Doks theme.

## Quick Start

### Development Build (Local Testing)

```bash
cd docs
hugo server --environment development
```

Access at: http://localhost:1313/

### Production Build

```bash
cd docs
HUGO_ENV=production hugo --minify --gc
```

Outputs to `public/` directory.

### Next/Staging Build

```bash
cd docs
HUGO_ENV=next hugo --minify --gc
```

## Configuration

Base configuration: `config/_default/hugo.toml`

Environment overrides:
- `config/development/hugo.toml` - localhost (http://localhost:1313/)
- `config/production/hugo.toml` - GitHub Pages (https://christianf88.github.io/flokbn/)
- `config/next/hugo.toml` - staging/preview

### baseURL Importance

The `baseURL` must match your deployment path:
- GitHub Pages subdirectory deployment requires full path with `/flokbn/`
- Local development uses `localhost:1313` without subdirectory
- Wrong baseURL breaks internal navigation links

Hugo loads environment-specific configs automatically based on `--environment` flag or `HUGO_ENV` variable.
