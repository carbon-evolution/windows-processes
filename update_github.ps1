# PowerShell script to update GitHub repository

Write-Host "===== Windows Process Analyzer: GitHub Update Script =====" -ForegroundColor Cyan
Write-Host ""

# Check for staged changes
$status = git status --porcelain
if ($status) {
    Write-Host "Changes detected in the following files:" -ForegroundColor Yellow
    git status --short
    Write-Host ""
}

# Prompt for commit message
$commitMessage = Read-Host "Enter a commit message (leave empty to abort)"
if (-not $commitMessage) {
    Write-Host "No commit message provided. Operation aborted." -ForegroundColor Red
    exit
}

# Add all files
Write-Host "Adding files to Git..." -ForegroundColor Green
git add .

# Commit changes
Write-Host "Committing changes with message: '$commitMessage'..." -ForegroundColor Green
git commit -m $commitMessage

# Check if remote exists
$remoteExists = git remote -v | Where-Object { $_ -match "origin" }
if (-not $remoteExists) {
    $repoUrl = Read-Host "Remote 'origin' not found. Enter your GitHub repository URL (https://github.com/username/repo.git)"
    if ($repoUrl) {
        git remote add origin $repoUrl
    } else {
        Write-Host "No repository URL provided. Push aborted." -ForegroundColor Red
        exit
    }
}

# Push to GitHub
Write-Host "Pushing to GitHub..." -ForegroundColor Green
git push origin main

if ($LASTEXITCODE -eq 0) {
    Write-Host "Successfully updated GitHub repository!" -ForegroundColor Green
} else {
    Write-Host "Failed to push to GitHub. See error message above." -ForegroundColor Red
    Write-Host "You may need to set up authentication or pull changes first." -ForegroundColor Yellow
    Write-Host "See GITHUB_SETUP.md for troubleshooting." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "===== Operation completed =====" -ForegroundColor Cyan 