"use client";

import { ThemeProvider as NextThemesProvider } from "next-themes";

/** Wraps the app in next-themes so the sidebar/toaster can flip light/dark. */
export function ThemeProvider({
  children,
  ...props
}: React.ComponentProps<typeof NextThemesProvider>) {
  return <NextThemesProvider {...props}>{children}</NextThemesProvider>;
}
