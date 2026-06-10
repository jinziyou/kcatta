import { Search } from "lucide-react";
import Link from "next/link";

import { EmptyState } from "@/components/states";
import { Button } from "@/components/ui/button";

// Global 404 boundary, hit when a detail page calls notFound() (an unknown
// report/alert/attack-path id). Uses the shared EmptyState so it matches the
// list pages' empty styling instead of Next's bare default, and offers a way back.
export default function NotFound() {
  return (
    <div className="mx-auto w-full max-w-6xl flex-1 p-6 sm:p-8">
      <EmptyState
        icon={Search}
        title="未找到"
        description="请求的资源不存在或已不可用。"
      >
        <Button render={<Link href="/" />}>返回概览</Button>
      </EmptyState>
    </div>
  );
}
