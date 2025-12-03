# How to release

## Create and push to a new release branch

1. Check out the `main` branch and make sure that you're on the newest version.

    `$ git switch main && git pull`

2. Make sure the version in the `package.json` file matches the version you're intending to release.

3. Create a new version branch with the naming `release/<version>` (do not include any postfix)

    `$ git switch -c release/<version>`

4. Push the release branch to the remote repository. This will trigger the release pipeline that builds an release to publish.

    `$ git push origin release/<version>`

5. Still on the release branch, create a version tag and push it

    ```shell
    $ git tag <version>
    $ git push origin <version>
    ```

## Increment version for future development

You've created a release for the current version, but now we need to bump the version as preparation for future development. This is done in the root `package.json`, back on the `main` branch.

1. Return to the `main` branch and make sure you're up-to-date

    `$ git switch main`

2. Create a new `chore` branch

    `$ git switch -c chore/update-version`

3. Bump the NPM package version:

    `$ npm version minor --no-git-tag-version`

4. Stage the changed files

    `$ git add package.json package-lock.json`

5. Commit the changes with a commit message like this

    ```
    chore: Bump version to <new_version>

    Relates-to: <release ticket number>
    ```

6. Push your new branch

    `$ git push origin chore/update-version`

7. Create a merge request into `main`.

Once the merge request was approved and merged, development can continue for the next version.

## Finishing Up

Make sure to release the matching version in Jira and create a new Jira release for the new version.

That's it, the release should be done! 🥳
