# github-app-credential-helper

`github-app-credential-helper` is a Git credential helper that uses GitHub App credentials to obtain access tokens. To use this tool, you need to set the environment variables `GITHUB_APP_ID`, `GITHUB_INSTALLATION_ID`, and `GITHUB_PRIVATE_KEY_PATH` to the appropriate values, and configure Git to use this helper:
```
git config --global credential.helper /usr/local/bin/github-app-credential-helper
```

You can now use Git as you normally would, and the credential helper will automatically use your GitHub App credentials to authenticate your requests. Make sure the GitHub App has the required permissions for the repositories you're accessing. You may need to grant additional repository or organization-level permissions depending on your use case.
