import { Skeleton } from "@/components/ui/skeleton";

// Root loading UI shown during navigation while a force-dynamic page awaits
// analyzer server-side. Without it, a slow analyzer round-trip leaves the user on a
// blank/frozen view with no feedback. A lightweight skeleton fills the gap.
export default function Loading() {
  return (
    <div className="mx-auto w-full max-w-6xl flex-1 p-6 sm:p-8">
      <div className="mb-8 flex flex-col gap-2">
        <Skeleton className="h-7 w-56" />
        <Skeleton className="h-4 w-80" />
      </div>
      <div className="flex flex-col gap-4">
        {[0, 1, 2].map((i) => (
          <div key={i} className="bg-card flex flex-col gap-3 rounded-xl border p-5">
            <div className="flex items-center justify-between">
              <Skeleton className="h-5 w-40" />
              <Skeleton className="h-5 w-16" />
            </div>
            <Skeleton className="h-4 w-full" />
            <Skeleton className="h-4 w-2/3" />
          </div>
        ))}
      </div>
    </div>
  );
}
