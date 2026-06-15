# Documentation Deployment Guide

This guide explains how to deploy the flokbn documentation to GitHub Pages.

## Prerequisites

- Repository with GitHub Pages enabled
- GitHub Actions enabled
- Hugo Extended v0.128.0 or higher (for local builds)
- Node.js v20.11.0+ (for Doks theme)

## Automatic Deployment

The documentation is automatically built and deployed to GitHub Pages whenever changes are pushed to the `main` branch in the `docs/` directory.

### GitHub Repository Settings

To enable GitHub Pages for this repository:

1. Go to your repository on GitHub
2. Navigate to **Settings** → **Pages**
3. Under **Source**, select **GitHub Actions**
4. Save the settings

The deployment workflow (`.github/workflows/docs.yml`) will automatically:
- Build the Hugo site
- Deploy it to GitHub Pages
- Make it available at `https://christianf88.github.io/flokbn/`

### Workflow Triggers

The documentation workflow runs when:
- Changes are pushed to the `docs/` directory on the `main` branch
- Changes are made to `.github/workflows/docs.yml`
- Manually triggered via **Actions** → **Deploy Documentation** → **Run workflow**

## Local Development

### Setup

1. Install Hugo Extended (v0.128.0+):
   ```bash
   # On Ubuntu/Debian
   wget https://github.com/gohugoio/hugo/releases/download/v0.128.0/hugo_extended_0.128.0_linux-amd64.deb
   sudo dpkg -i hugo_extended_0.128.0_linux-amd64.deb

   # On macOS
   brew install hugo

   # Verify version
   hugo version  # Should show v0.128.0 or higher with "extended"
   ```

2. Install Node.js dependencies:
   ```bash
   cd docs
   npm install
   ```

### Development Server

Run the local development server with hot-reload:

```bash
cd docs
npm run dev
```

The site will be available at `http://localhost:1313/flokbn/`

### Build Locally

Build the production site:

```bash
cd docs
npm run build
```

The built site will be in `docs/public/`

### Preview Production Build

```bash
cd docs
npm run preview
```

## Content Management

### Directory Structure

```
docs/
├── content/
│   ├── _index.md (Homepage)
│   ├── docs/
│   │   ├── _index.md
│   │   ├── getting-started/
│   │   ├── usage/
│   │   ├── configuration/
│   │   └── advanced/
│   └── blog/ (optional)
├── config/
│   └── _default/
│       ├── hugo.toml
│       ├── params.toml
│       └── menus/
└── static/ (images, files)
```

### Adding New Pages

1. Create a new markdown file in the appropriate section:
   ```bash
   cd docs
   npm run create -- content/docs/section/page.md
   ```

2. Add frontmatter:
   ```yaml
   ---
   title: "Page Title"
   description: "Short description"
   weight: 100
   ---
   ```

3. Write content in markdown
4. Commit and push - it will auto-deploy

### Navigation

Edit `docs/config/_default/menus/menus.en.toml` to modify navigation menus.

## Troubleshooting

### Build Fails Locally

**Error**: `function "try" not defined`
- **Cause**: Hugo version is too old
- **Solution**: Upgrade to Hugo Extended v0.128.0+

**Error**: `EBADENGINE Unsupported engine`
- **Cause**: Node.js version is too old
- **Solution**: Upgrade to Node.js v20.11.0+

### GitHub Pages Not Updating

1. Check the Actions tab for workflow errors
2. Verify GitHub Pages source is set to "GitHub Actions"
3. Check repository permissions for GitHub Actions
4. Manually trigger the workflow: Actions → Deploy Documentation → Run workflow

### Links Not Working

- Ensure all internal links start with `/docs/`
- Use relative links for images: `![Alt](./image.png)`
- Check `baseURL` in `config/_default/hugo.toml`

## Monitoring

### View Deployment Status

1. Go to **Actions** tab in GitHub
2. Click on the latest "Deploy Documentation" workflow
3. Check build and deploy steps

### Access Logs

- Build logs: Available in GitHub Actions workflow runs
- Deployment logs: Available in the deploy step

## Configuration

### Base URL

The base URL is configured in `docs/config/_default/hugo.toml`:

```toml
baseurl = "https://christianf88.github.io/flokbn/"
```

Change this if deploying to a different URL or custom domain.

### Theme Updates

To update the Doks theme dependencies:

```bash
cd docs
npm update
```

## Custom Domain (Optional)

To use a custom domain:

1. Add a `CNAME` file to `docs/static/`:
   ```bash
   echo "docs.flokbn.example.com" > docs/static/CNAME
   ```

2. Update DNS settings to point to GitHub Pages:
   ```
   CNAME record: docs -> christianf88.github.io
   ```

3. Update `baseurl` in `hugo.toml` to match your domain

4. Enable HTTPS in repository Settings → Pages

## Performance

### Build Time

- Average build time: ~30 seconds
- Full workflow (build + deploy): ~1-2 minutes

### Optimization

- Images are automatically optimized by the Doks theme
- CSS/JS are minified in production builds
- Search index is generated for fast client-side search

## Support

For issues with:
- **Hugo/Doks**: Check [Doks documentation](https://getdoks.org/)
- **GitHub Pages**: Check [GitHub Pages docs](https://docs.github.com/en/pages)
- **flokbn content**: Open an issue in the repository
