#!/bin/bash
# Script to completely remove commit d205785 from history

set -e

cd "$(dirname "$0")"

echo "Removing commit d205785 from git history..."

# Stash any changes
git stash 2>/dev/null || true

# Find the commit before d205785
BEFORE_COMMIT=$(git log --oneline | grep -B1 "d205785" | head -1 | awk '{print $1}')

if [ -z "$BEFORE_COMMIT" ]; then
    BEFORE_COMMIT="0a181a3"
fi

echo "Rebasing from $BEFORE_COMMIT..."

# Use filter-branch to remove the file from that specific commit
FILTER_BRANCH_SQUELCH_WARNING=1 git filter-branch --force --index-filter \
    'if git rev-list --count d205785..HEAD | grep -q "^0$"; then
        git rm --cached --ignore-unmatch web_app/deploy_config.example
    fi' \
    --prune-empty --tag-name-filter cat -- --all 2>&1 | tail -5 || {
    
    echo "Filter-branch approach didn't work. Trying interactive rebase..."
    
    # Alternative: interactive rebase to drop the commit
    export GIT_SEQUENCE_EDITOR="sed -i.bak '/^pick d205785/d'"
    git rebase -i "$BEFORE_COMMIT" 2>&1 || {
        echo "Rebase failed. Manual intervention needed."
        echo ""
        echo "Option 1: Use GitHub web interface to allow the secret:"
        echo "  https://github.com/CupofJavad/Anti-Language-Encryption-Tool-/security/secret-scanning/unblock-secret/37Lc2WhbqSk31tw4aEfqGTo8Phd"
        echo ""
        echo "Option 2: Create a new branch without that commit:"
        echo "  git checkout -b clean-main 0a181a3"
        echo "  git cherry-pick a643720"
        echo "  git cherry-pick 90a2979"
        echo "  git push origin clean-main"
        exit 1
    }
}

# Verify the commit is gone
if git log --oneline | grep -q "d205785"; then
    echo "⚠️  Commit d205785 still in history"
    echo "Creating clean branch instead..."
    
    git checkout -b clean-main 0a181a3 2>/dev/null || git checkout clean-main
    git cherry-pick a643720 2>&1 || true
    git cherry-pick 90a2979 2>&1 || true
    
    echo "✅ Created clean-main branch without the problematic commit"
    echo "Push with: git push origin clean-main"
else
    echo "✅ Commit d205785 removed from history!"
    echo "You can now push with: git push origin main --force-with-lease"
fi

git stash pop 2>/dev/null || true

