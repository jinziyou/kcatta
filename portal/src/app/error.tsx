"use client";

import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

// Route-segment error boundary. Detail pages (reports/alerts/attack-paths) re-throw
// every non-404 error — most often the fusion API being unreachable. Without this
// boundary those surfaced Next's default error screen, inconsistent with the friendly
// card the list pages render. (Next 16 names the retry callback `unstable_retry`, not
// the older `reset`.)
export default function Error({
  error,
  unstable_retry,
}: {
  error: Error & { digest?: string };
  unstable_retry: () => void;
}) {
  return (
    <div className="mx-auto w-full max-w-5xl flex-1 p-6 sm:p-10">
      <Card className="border-destructive/40">
        <CardHeader>
          <CardTitle className="text-destructive">Cannot reach fusion API</CardTitle>
          <CardDescription>{error.message}</CardDescription>
        </CardHeader>
        <CardContent className="text-muted-foreground text-sm">
          Make sure <span className="font-mono">fusion-api</span> is running and that
          <span className="font-mono"> NEXT_PUBLIC_FUSION_BASE_URL</span> points at it.
          <div className="mt-4">
            <button
              type="button"
              onClick={() => unstable_retry()}
              className="text-foreground hover:bg-muted rounded-md border px-3 py-1.5"
            >
              Try again
            </button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
