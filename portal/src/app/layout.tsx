import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import Link from "next/link";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "cyber-posture portal",
  description: "Security posture management dashboard",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      className={`${geistSans.variable} ${geistMono.variable} h-full antialiased`}
    >
      <body className="min-h-full flex flex-col">
        <nav className="border-b">
          <div className="mx-auto flex w-full max-w-5xl items-center gap-6 px-6 py-3 sm:px-10">
            <span className="text-sm font-semibold tracking-tight">cyber-posture</span>
            <Link
              href="/"
              className="text-muted-foreground hover:text-foreground text-sm transition-colors"
            >
              Asset reports
            </Link>
            <Link
              href="/vulnerabilities"
              className="text-muted-foreground hover:text-foreground text-sm transition-colors"
            >
              Findings
            </Link>
            <Link
              href="/flows"
              className="text-muted-foreground hover:text-foreground text-sm transition-colors"
            >
              Flows
            </Link>
            <Link
              href="/alerts"
              className="text-muted-foreground hover:text-foreground text-sm transition-colors"
            >
              Alerts
            </Link>
          </div>
        </nav>
        {children}
      </body>
    </html>
  );
}
