export default function HomePage() {
  return (
    <main>
      <h1>rust-auth · Next.js example</h1>
      <p>
        This app demonstrates edge JWT verification via WASM with{" "}
        <code>@bymax-one/rust-auth/nextjs</code>: the middleware proxy verifies a
        backend-signed HS256 token at the edge before letting a request reach a
        protected route.
      </p>
      <ul>
        <li>
          <a href="/login" data-testid="home-login-link">
            Sign in
          </a>
        </li>
        <li>
          <a href="/dashboard">Dashboard (protected)</a>
        </li>
      </ul>
    </main>
  );
}
