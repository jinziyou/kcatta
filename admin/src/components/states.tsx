import { TriangleAlert } from "lucide-react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import {
  Empty,
  EmptyContent,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty";
import type { LucideIcon } from "lucide-react";

/** Dashed-border empty placeholder with an icon, title, body, and optional CTA. */
export function EmptyState({
  icon: Icon,
  title,
  description,
  children,
}: {
  icon: LucideIcon;
  title: React.ReactNode;
  description?: React.ReactNode;
  children?: React.ReactNode;
}) {
  return (
    <Empty className="border">
      <EmptyHeader>
        <EmptyMedia variant="icon">
          <Icon />
        </EmptyMedia>
        <EmptyTitle>{title}</EmptyTitle>
        {description && <EmptyDescription>{description}</EmptyDescription>}
      </EmptyHeader>
      {children && <EmptyContent>{children}</EmptyContent>}
    </Empty>
  );
}

/** Destructive alert used when a analyzer API call fails. */
export function ErrorState({ message }: { message: string }) {
  return (
    <Alert variant="destructive">
      <TriangleAlert />
      <AlertTitle>无法连接 analyzer API</AlertTitle>
      <AlertDescription>
        {message}
        <p className="text-muted-foreground mt-1">
          请确认 <span className="font-mono">analyzer-api</span> 正在运行，且{" "}
          <span className="font-mono">NEXT_PUBLIC_ANALYZER_BASE_URL</span> 指向正确地址。
        </p>
      </AlertDescription>
    </Alert>
  );
}
