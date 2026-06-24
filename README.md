# vibebase-client

The client for a [Vibebase](https://vibebase.io) backend — Postgres + auth + file storage + vector search, fully typed.

## Install

```bash
npm install vibebase-client
```

Set `DATABASE_URL` and `AUTH_SECRET` in your environment (Vibebase writes them to `.env.local` when it provisions your backend).

## Use

```js
import { signUp, signIn, getUser, addDocument, searchSimilar, putFile, migrate } from 'vibebase-client';

const { user, token } = await signUp('a@b.com', 'secret');
const me = await getUser(token);
```

## What's included

- **Auth** — `signUp` / `signIn` / `getUser` / `signOut` / `signOutAll`, password reset, email verification, login rate-limiting
- **Social login** — `oauthRedirectUrl` / `oauthCallback` (Google, GitHub)
- **Vector search** — `addDocument` / `searchSimilar` (pgvector, for RAG)
- **File storage** — `putFile` / `getFile` / `listFiles` / `deleteFile`
- **Change feed** — `changesSince` / `onChange`
- **Schema** — `migrate` (versioned migrations) / `insertMany` (bulk seed)
- **Raw SQL** — `sql\`...\`` (parameterized, injection-safe)

Full TypeScript types ship with the package.

## License

MIT
