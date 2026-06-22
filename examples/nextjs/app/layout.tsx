import type { ReactNode } from "react";

export const metadata = {
  title: "rust-auth · nextjs example",
  description: "Edge JWT verification via WASM with @bymax-one/rust-auth/nextjs.",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
