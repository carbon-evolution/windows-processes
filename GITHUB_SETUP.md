# GitHub Repository Setup Guide

This guide will help you set up and connect your local project to GitHub.

## Prerequisites

1. [Git](https://git-scm.com/downloads) installed locally
2. [GitHub](https://github.com/) account

## Setting Up Your Repository

### If starting with a local project that's not yet on GitHub:

1. Create a new repository on GitHub
   - Go to [GitHub](https://github.com/)
   - Click "New repository" 
   - Name your repository (e.g., "windows-process-analyzer")
   - Choose public or private visibility
   - Do NOT initialize with README, .gitignore, or license (we already have these)
   - Click "Create repository"

2. Connect your local repository to GitHub
   ```bash
   # Navigate to your project directory
   cd path/to/windows-process-analyzer
   
   # Initialize git if not already done
   git init
   
   # Add all files
   git add .
   
   # Commit the files
   git commit -m "Initial commit"
   
   # Add the GitHub repository as a remote
   git remote add origin https://github.com/YOUR-USERNAME/windows-process-analyzer.git
   
   # Push your code to GitHub
   git push -u origin main
   ```

### If the repository is already on GitHub but there are issues:

1. Verify remote configuration
   ```bash
   git remote -v
   ```

2. Update remote if needed
   ```bash
   git remote set-url origin https://github.com/YOUR-USERNAME/windows-process-analyzer.git
   ```

3. Pull latest changes
   ```bash
   git pull origin main
   ```

4. Push your changes
   ```bash
   git push origin main
   ```

## Common Issues and Solutions

### Authentication Issues

If you're having authentication issues, consider:

1. Using GitHub CLI for authentication:
   ```bash
   # Install GitHub CLI
   # Then authenticate
   gh auth login
   ```

2. Using a Personal Access Token:
   - Go to GitHub → Settings → Developer settings → Personal access tokens
   - Generate a new token with appropriate permissions
   - Use the token as your password when pushing

### Other Common Issues

- **"Updates were rejected"**: Pull the latest changes before pushing
  ```bash
  git pull origin main
  ```

- **Merge conflicts**: Resolve conflicts in the files, then:
  ```bash
  git add .
  git commit -m "Resolve merge conflicts"
  git push origin main
  ```

## Setting Up GitHub Actions

The workflow files created in the `.github/workflows` directory will automatically run when you push to GitHub, helping with continuous integration. 