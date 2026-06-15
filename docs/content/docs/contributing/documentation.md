---
title: "Documentation"
description: "Guide for updating flokbn documentation"
summary: "How to build and update the Hugo-based documentation site"
date: 2025-10-09T10:00:00+00:00
lastmod: 2025-11-26T10:00:00+00:00
draft: false
weight: 510
toc: true
seo:
  title: "Contributing to flokbn Documentation"
  description: "Learn how to update the flokbn documentation site"
  canonical: ""
  noindex: false
---

flokbn documentation uses [Hugo](https://gohugo.io/) extended with the [Thulite/Doks](https://github.com/thuliteio/doks) theme.

## Local Development

### Start Server

```bash
cd docs
hugo server --environment development
```

Access at: http://localhost:1313/

### Build for Production

```bash
cd docs
HUGO_ENV=production hugo --minify --gc
```

## Page Structure

Every page needs front matter:

```yaml
---
title: "Page Title"
description: "Brief description"
summary: "Longer summary for search"
date: 2025-10-09T10:00:00+00:00
lastmod: 2025-10-09T10:00:00+00:00
draft: false
weight: 100
toc: true
---
```

### Weight System

Controls page order (lower = first):

- Getting Started: 100-120
- Reference: 200-260
- Architecture: 400-420
- Contributing: 500-550
- Guides: 800-840

### Documentation Principles

- **Single source of truth**: Parameter details live only in `reference/`. Guides link to them.
- **Reference pages are exhaustive**: Every flag, format, and option documented.
- **Guide pages are narrative**: Step-by-step walkthroughs that link to reference for details.
- **No duplication**: Config examples, file formats, and parameter tables appear in exactly one place.

## Writing Content

### Code Blocks

````markdown
```bash
./flokbn static --logfile access.log --plain
```
````

Supported: `bash`, `go`, `toml`, `yaml`, `json`, `nginx`

### Internal Links

```markdown
[Link Text]({{</* relref "/docs/section/page/" */>}})
```

Always use trailing slash for section links.

### Cross-Referencing

When writing guide content that mentions parameters, file formats, or config options, link to the canonical reference page instead of repeating the content:

```markdown
See [Clustering]({{</* relref "/docs/reference/clustering/" */>}}) for parameter details.
```

## Common Tasks

### Create New Page

```bash
cd docs
hugo new content/docs/section/page-name.md
```

### Update Existing Page

1. Edit the markdown file
2. Update `lastmod` date
3. Test with `hugo server`

## Deployment

Documentation deploys automatically via GitHub Actions when pushed to `main`.

## Documentation Checklist

Before submitting docs PR:

- [ ] Ran `hugo server` and verified changes
- [ ] Updated `lastmod` date
- [ ] All `{{</* relref */>}}` links resolve
- [ ] No content duplicated from reference pages
- [ ] Used appropriate weight for ordering
