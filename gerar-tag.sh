#!/bin/bash

# Ensure the repository is up-to-date
git pull origin main

# Fetch the latest version tag
latest_tag=$(git describe --tags $(git rev-list --tags --max-count=1))

# Extract the current digit and increment it
if [[ $latest_tag =~ v0\.0\.[0-9]+ ]]; then
    current_digit=$(echo $latest_tag | grep -oE '[0-9]+$')
    new_digit=$((current_digit + 1))
else
    new_digit=1
fi

# Create the new version tag
new_version="v0.0.$new_digit"

# Ensure the new version tag does not already exist
while git rev-parse "refs/tags/$new_version" >/dev/null 2>&1; do
    new_digit=$((new_digit + 1))
    new_version="v0.0.$new_digit"
done

# Create the new tag
git tag $new_version

# Push the commit and the new tag to GitHub
git push origin main
git push origin $new_version
