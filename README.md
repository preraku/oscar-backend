# Oscar Nominations Backend

Backend to the [Oscar Nominations Checklist](https://github.com/preraku/oscar-checklist).

Set up for development:

1. Install Bun. https://bun.sh/docs/installation
2. Clone the repo.
3. Navigate to the repo in your shell.
4. Run `bun install`
5. Create a `.dev.vars` file in the root of the repo. (e.g. `oscars-backend/.dev.vars`). It should look like the following:

```
[vars]
JWT_SECRET_KEY=my_jwt_secret_key
ADMIN_USERNAME=my_admin_username
ADMIN_PASSWORD=my_admin_password
SALT_ROUNDS=8
```

6. Run `npm run dev`
7. You will likely be required to sign into/up for Cloudflare if you haven't already.
8. Go to http://localhost:8787/. You should see `Hello!`.

To set up to work with the checklist front end, see its [README.md](https://github.com/preraku/oscar-checklist?tab=readme-ov-file).
