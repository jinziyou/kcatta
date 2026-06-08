import { Card, CardContent, CardHeader } from "@/components/ui/card";

// Root loading UI shown during navigation while a force-dynamic page awaits
// fusion server-side. Without it, a slow fusion round-trip leaves the user on a
// blank/frozen view with no feedback. A lightweight skeleton fills the gap.
export default function Loading() {
  return (
    <div className="mx-auto w-full max-w-5xl flex-1 p-6 sm:p-10">
      <div className="bg-muted mb-6 h-7 w-48 animate-pulse rounded-md" />
      <div className="space-y-4">
        {[0, 1, 2].map((i) => (
          <Card key={i}>
            <CardHeader>
              <div className="bg-muted h-5 w-40 animate-pulse rounded-md" />
              <div className="bg-muted h-4 w-64 animate-pulse rounded-md" />
            </CardHeader>
            <CardContent>
              <div className="bg-muted h-4 w-full animate-pulse rounded-md" />
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
