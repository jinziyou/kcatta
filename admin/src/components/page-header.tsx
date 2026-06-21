import { cn } from "@/lib/utils";

/**
 * Consistent page title + description + optional right-aligned actions.
 * The `h1` renders in the serif display face (via globals `h1`); pass an
 * optional `eyebrow` (classification / breadcrumb, e.g. `扫描中心 / 任务`) to print
 * a mono uppercase tick label above it.
 */
export function PageHeader({
  title,
  description,
  actions,
  eyebrow,
  className,
}: {
  title: React.ReactNode;
  description?: React.ReactNode;
  actions?: React.ReactNode;
  eyebrow?: React.ReactNode;
  className?: string;
}) {
  return (
    <header className={cn("mb-7 flex flex-wrap items-end justify-between gap-4", className)}>
      <div className="flex min-w-0 flex-col gap-2.5">
        {eyebrow && (
          <span className="lp-eyebrow" data-tick>
            {eyebrow}
          </span>
        )}
        <h1 className="text-2xl leading-[1.1] font-semibold tracking-tight sm:text-[1.75rem]">
          {title}
        </h1>
        {description && (
          <p className="text-muted-foreground max-w-2xl text-sm leading-relaxed">{description}</p>
        )}
      </div>
      {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
    </header>
  );
}
