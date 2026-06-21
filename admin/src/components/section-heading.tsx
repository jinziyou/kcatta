import { cn } from "@/lib/utils";

/**
 * Dossier section divider: a mono `01`-style index, a serif title, then a
 * hairline rule that flexes to fill the row, with optional trailing content
 * (e.g. a `.lp-tag`). Signature element of the Intelligence Brief layout.
 */
export function SectionHeading({
  index,
  title,
  trailing,
  className,
  id,
}: {
  index?: string;
  title: React.ReactNode;
  trailing?: React.ReactNode;
  className?: string;
  id?: string;
}) {
  return (
    <div className={cn("mb-4 flex items-baseline gap-3.5", className)}>
      {index && (
        <span className="lp-mono text-muted-foreground text-[0.6875rem] tracking-[0.1em]">
          {index}
        </span>
      )}
      <h2 id={id} className="font-heading text-lg leading-none font-medium tracking-tight">
        {title}
      </h2>
      <span className="lp-rule self-center" aria-hidden />
      {trailing}
    </div>
  );
}
