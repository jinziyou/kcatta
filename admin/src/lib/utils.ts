import { clsx, type ClassValue } from "clsx"
import { twMerge } from "tailwind-merge"

/** Merge class names with `clsx` and dedupe conflicting Tailwind utilities via `tailwind-merge`. */
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}
