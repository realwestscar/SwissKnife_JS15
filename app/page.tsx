export default function Home() {
  return (
    <main className="mx-auto min-h-screen max-w-5xl px-4 py-16">
      <section className="rounded-lg border border-border bg-secondary/20 p-8">
        <p className="mb-3 text-xs uppercase tracking-wider text-muted-foreground">SwissKnife</p>
        <h1 className="mb-4 text-3xl font-bold tracking-tight md:text-4xl">Backend-first Next.js template</h1>
        <p className="max-w-3xl text-muted-foreground">
          This starter keeps only essentials: authentication routes, user routes, validation, error handling, and shared middleware.
        </p>
      </section>

      <section className="mt-8 grid gap-4 md:grid-cols-2">
        <div className="rounded-lg border border-border bg-secondary/20 p-6">
          <h2 className="mb-3 text-lg font-semibold">Core API</h2>
          <ul className="space-y-2 text-sm text-muted-foreground">
            <li><code>POST /api/auth/register</code></li>
            <li><code>POST /api/auth/login</code></li>
            <li><code>POST /api/auth/refresh</code></li>
            <li><code>POST /api/auth/logout</code></li>
            <li><code>POST /api/auth/forgot-password</code></li>
            <li><code>POST /api/auth/reset-password</code></li>
            <li><code>GET /api/auth/verify-email</code></li>
            <li><code>GET /api/users</code></li>
            <li><code>GET /api/users/[id]</code></li>
            <li><code>PATCH /api/users/[id]</code></li>
            <li><code>DELETE /api/users/[id]</code></li>
            <li><code>GET /api/health/live</code></li>
            <li><code>GET /api/health/ready</code></li>
          </ul>
        </div>

        <div className="rounded-lg border border-border bg-secondary/20 p-6">
          <h2 className="mb-3 text-lg font-semibold">Run Locally</h2>
          <div className="rounded-md bg-background p-3 font-mono text-sm">
            <p>cp .env.example .env.local</p>
            <p>corepack pnpm install</p>
            <p>corepack pnpm dev</p>
          </div>
        </div>
      </section>
    </main>
  );
}
