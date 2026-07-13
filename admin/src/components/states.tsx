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
    <Empty>
      <EmptyHeader>
        <EmptyMedia
          variant="icon"
          className="bg-primary/10 text-primary size-10 [&_svg:not([class*='size-'])]:size-5"
        >
          <Icon />
        </EmptyMedia>
        <EmptyTitle>{title}</EmptyTitle>
        {description && <EmptyDescription>{description}</EmptyDescription>}
      </EmptyHeader>
      {children && <EmptyContent>{children}</EmptyContent>}
    </Empty>
  );
}

/** Destructive alert used when a Form API call fails. */
export function ErrorState({ message }: { message: string }) {
  return (
    <Alert variant="destructive">
      <TriangleAlert />
      <AlertTitle>无法连接 Form API</AlertTitle>
      <AlertDescription>
        {message}
        <p className="text-muted-foreground mt-1">
          请确认 <span className="font-mono">form-api</span> 正在运行，且{" "}
          <span className="font-mono">FORM_BASE_URL</span> 指向正确地址。
        </p>
      </AlertDescription>
    </Alert>
  );
}
