# GitHub Pages Setup Instructions

Follow these steps to enable automatic documentation deployment to GitHub Pages.

## 1. Enable GitHub Pages

1. Navigate to your repository on GitHub: https://github.com/ChristianF88/flokbn

2. Click on **Settings** (gear icon in the top navigation)

3. In the left sidebar, scroll down and click **Pages**

4. Under **Build and deployment**:
   - **Source**: Select **GitHub Actions** from the dropdown
   - This allows the documentation workflow to deploy automatically

5. Click **Save** (if applicable)

## 2. Verify Workflow Permissions

Ensure GitHub Actions has the correct permissions:

1. Go to **Settings** → **Actions** → **General**

2. Scroll to **Workflow permissions**

3. Select **Read and write permissions**

4. Enable **Allow GitHub Actions to create and approve pull requests** (optional, but recommended)

5. Click **Save**

## 3. Push Documentation Changes

Once configured, the documentation will automatically deploy when you push changes:

```bash
git add docs/
git add .github/workflows/docs.yml
git commit -m "Add Hugo documentation with Doks theme"
git push origin main
```

## 4. Monitor Deployment

1. Go to the **Actions** tab in your repository

2. You should see a workflow run named **Deploy Documentation**

3. Click on it to see the build and deployment progress

4. The workflow consists of two jobs:
   - **Build Hugo Site**: Compiles the documentation
   - **Deploy to GitHub Pages**: Publishes to GitHub Pages

Expected build time: ~1-2 minutes

## 5. Access Your Documentation

Once the workflow completes successfully:

**Documentation URL**: https://christianf88.github.io/flokbn/

The documentation will be live and accessible to everyone.

## 6. Verify Deployment

Test that the documentation is working:

1. Visit https://christianf88.github.io/flokbn/
2. Check that the homepage loads
3. Navigate to the documentation sections
4. Test the search functionality
5. Verify mobile responsiveness

## Troubleshooting

### Workflow Fails

**Issue**: Build job fails with permissions error
- **Solution**: Check that "Read and write permissions" are enabled in Settings → Actions → General

**Issue**: Deploy job fails
- **Solution**: Verify that GitHub Pages source is set to "GitHub Actions"

**Issue**: SCSS/SASS compilation error
- **Solution**: The workflow uses Hugo Extended v0.128.0 which includes SASS support. If it still fails, check the Hugo version in `.github/workflows/docs.yml`

### 404 Error on Documentation Site

**Issue**: Site shows 404 Not Found
- **Solution 1**: Wait 2-3 minutes after deployment completes
- **Solution 2**: Verify the baseURL in `docs/config/_default/hugo.toml` matches your GitHub Pages URL
- **Solution 3**: Check that the deploy step completed successfully in Actions

### Old Content Showing

**Issue**: Documentation not updating after push
- **Solution**: Clear browser cache or use Ctrl+Shift+R (hard refresh)
- Check that the workflow ran successfully in the Actions tab

### Links Broken

**Issue**: Internal links return 404
- **Solution**: Ensure all internal links in markdown use the format `/docs/section/page/`
- Check that the baseURL includes `/flokbn/` at the end

## Manual Deployment Trigger

You can manually trigger a documentation deployment:

1. Go to **Actions** tab
2. Click **Deploy Documentation** in the left sidebar
3. Click **Run workflow** button
4. Select the `main` branch
5. Click **Run workflow**

This is useful for:
- Testing the deployment process
- Rebuilding without code changes
- Forcing a fresh deployment

## Future Updates

To update documentation content:

1. Edit files in `docs/content/docs/`
2. Commit and push to `main` branch
3. Documentation automatically rebuilds and deploys
4. Changes are live in 1-2 minutes

No additional configuration needed!

## Custom Domain (Optional)

To use a custom domain like `docs.flokbn.io`:

1. Add a `CNAME` file:
   ```bash
   echo "docs.flokbn.io" > docs/static/CNAME
   git add docs/static/CNAME
   git commit -m "Add custom domain"
   git push
   ```

2. Configure DNS:
   - Add a CNAME record pointing to `christianf88.github.io`
   - Or add A records pointing to GitHub Pages IPs

3. In GitHub Settings → Pages:
   - Enter your custom domain
   - Enable "Enforce HTTPS"

4. Update `docs/config/_default/hugo.toml`:
   ```toml
   baseurl = "https://docs.flokbn.io/"
   ```

## Support

If you encounter issues:
- Check [Hugo documentation](https://gohugo.io/documentation/)
- Review [Doks theme docs](https://getdoks.org/)
- Consult [GitHub Pages documentation](https://docs.github.com/en/pages)
- Open an issue in the repository
