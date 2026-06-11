import Link from "next/link";

import { Badge } from "@/components/ui/badge";

/** A Badge wrapped in a Link; active uses a solid/colored fill, otherwise outline. */
export function FilterChip({
  href,
  label,
  active,
  activeClassName,
}: {
  href: string;
  label: string;
  active: boolean;
  activeClassName?: string;
}) {
  return (
    <Badge
      variant={active ? "default" : "outline"}
      className={active ? activeClassName : undefined}
      render={<Link href={href} />}
    >
      {label}
    </Badge>
  );
}
