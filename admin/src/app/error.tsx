"use client";

import { TriangleAlert } from "lucide-react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";

// Route-segment error boundary. Detail pages (reports/alerts/attack-paths) re-throw
// every non-404 error — most often the Form API being unreachable. Without this
// boundary those surfaced Next's default error screen, inconsistent with the friendly
// alert the list pages render. (Next 16 names the retry callback `unstable_retry`, not
// the older `reset`.)
//
// NOTE: these errors originate in Server Components, so in production Next redacts
// `error.message` to a generic string + `digest`. We therefore show a fixed
// description (and the digest for log correlation) rather than rendering
// `error.message`, which would be meaningless in prod.
export default function Error({
  error,
  unstable_retry,
}: {
  error: Error & { digest?: string };
  unstable_retry: () => void;
}) {
  return (
    <div className="mx-auto w-full max-w-6xl flex-1 p-6 sm:p-8">
      <Alert variant="destructive">
        <TriangleAlert />
        <AlertTitle>无法加载数据</AlertTitle>
        <AlertDescription>
          页面未能从 Form 获取数据。请稍后重试，若问题持续请检查 Form 服务状态。
          {error.digest ? (
            <p className="text-muted-foreground mt-1">
              错误编号 <span className="font-mono">{error.digest}</span>
            </p>
          ) : null}
        </AlertDescription>
      </Alert>
      <div className="mt-4">
        <Button variant="outline" onClick={() => unstable_retry()}>
          重试
        </Button>
      </div>
    </div>
  );
}
