#!/bin/bash

# Simple script to push web_app to GitHub
# Handles conflicts automatically

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}Preparing to push to GitHub...${NC}"

cd "$(dirname "$0")"

# Add all files
git add .

# Remove sensitive files
git reset HEAD secretes.txt 2>/dev/null || true
git reset HEAD web_app/deploy_config 2>/dev/null || true

# Commit if there are changes
if ! git diff --cached --quiet; then
    git commit -m "Add web application for DigitalOcean deployment" || true
fi

# Try to pull and merge
echo -e "${YELLOW}Pulling latest changes...${NC}"
git pull origin main --no-edit 2>&1 || {
    echo -e "${YELLOW}Merge conflict detected. Resolving...${NC}"
    # Keep our versions of conflicted files
    git checkout --ours .gitignore README.md forgotten_e2ee/gui.py requirements.txt 2>/dev/null || true
    git add .gitignore README.md forgotten_e2ee/gui.py requirements.txt 2>/dev/null || true
    git commit -m "Merge: Add web application" || true
}

# Push
echo -e "${YELLOW}Pushing to GitHub...${NC}"
git push origin main || {
    echo -e "${RED}Push failed. You may need to:${NC}"
    echo "1. Resolve conflicts manually"
    echo "2. Or run: git push origin main --force (if you're sure)"
    exit 1
}

echo -e "${GREEN}✅ Successfully pushed to GitHub!${NC}"
echo ""
echo "Now go to DigitalOcean and:"
echo "1. Refresh the page"
echo "2. Repository: CupofJavad/Anti-Language-Encryption-Tool-"
echo "3. Branch: main"
echo "4. Source directory: web_app"
echo "5. Click Next"

