import Link from "next/link";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

// Global 404 boundary, hit when a detail page calls notFound() (an unknown
// report/alert/attack-path id). Mirrors the list/error pages' Card styling
// instead of Next's bare default, and offers a way back.
export default function NotFound() {
  return (
    <div className="mx-auto w-full max-w-5xl flex-1 p-6 sm:p-10">
      <Card>
        <CardHeader>
          <CardTitle>Not found</CardTitle>
          <CardDescription>
            The requested resource does not exist or is no longer available.
          </CardDescription>
        </CardHeader>
        <CardContent className="text-sm">
          <Link href="/" className="text-foreground hover:bg-muted rounded-md border px-3 py-1.5">
            Back to overview
          </Link>
        </CardContent>
      </Card>
    </div>
  );
}
