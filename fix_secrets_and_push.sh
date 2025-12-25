#!/bin/bash
# Script to fix secret issues and push to GitHub

set -e

cd "$(dirname "$0")"

echo "Fixing secret issues in git history..."

# Remove secretes.txt from git if tracked
git rm --cached secretes.txt 2>/dev/null || true

# Make sure it's in .gitignore
if ! grep -q "secretes.txt" .gitignore 2>/dev/null; then
    echo "secretes.txt" >> .gitignore
    git add .gitignore
fi

# Fix deploy_config.example in current commit
if [ -f "web_app/deploy_config.example" ]; then
    sed -i '' 's/dop_v1_[a-zA-Z0-9_]*/your_api_token_here/g' web_app/deploy_config.example 2>/dev/null || \
    sed -i 's/dop_v1_[a-zA-Z0-9_]*/your_api_token_here/g' web_app/deploy_config.example
    git add web_app/deploy_config.example
fi

# Commit the fixes
git commit -m "Remove secrets from repository" 2>/dev/null || echo "No new changes to commit"

# Try to push
echo "Attempting to push..."
git push origin main 2>&1 || {
    echo ""
    echo "⚠️  Push failed. This is likely because:"
    echo "1. GitHub detected secrets in previous commits"
    echo "2. You may need to use GitHub's web interface to allow the push"
    echo ""
    echo "Options:"
    echo "A) Visit the GitHub links shown above to allow the secrets"
    echo "B) Or we can rewrite history to remove secrets (more complex)"
    echo ""
    echo "For now, your local commits are ready. You can:"
    echo "1. Push via GitHub Desktop"
    echo "2. Or allow the secrets via GitHub's web interface"
}

