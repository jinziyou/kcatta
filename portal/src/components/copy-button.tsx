"use client";

import { Check, Copy } from "lucide-react";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

/** Inline copy-to-clipboard control for ids/hashes; shows a check on success. */
export function CopyButton({ value, className }: { value: string; className?: string }) {
  const [copied, setCopied] = useState(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    } catch {
      // clipboard unavailable (e.g. insecure context) — silently ignore
    }
  }

  return (
    <Button
      type="button"
      variant="ghost"
      size="icon-xs"
      aria-label="复制"
      onClick={copy}
      className={cn("text-muted-foreground", className)}
    >
      {copied ? <Check className="size-3" /> : <Copy className="size-3" />}
    </Button>
  );
}

/** A monospace id with a trailing copy button. */
export function CopyableId({ value, className }: { value: string; className?: string }) {
  return (
    <span className={cn("inline-flex items-center gap-1 font-mono text-xs", className)}>
      <span className="truncate">{value}</span>
      <CopyButton value={value} />
    </span>
  );
}
