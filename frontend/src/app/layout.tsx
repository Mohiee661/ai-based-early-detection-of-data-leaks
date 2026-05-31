import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "DarkShield",
  description: "Supabase-backed monitoring for GitHub secret exposure.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark h-full antialiased">
      <body className="min-h-full bg-background text-foreground">
        {children}
      </body>
    </html>
  );
}
