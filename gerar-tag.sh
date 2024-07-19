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
git tag $new_version

# Push the commit and the new tag to GitHub
git push origin main
git push origin $new_version

