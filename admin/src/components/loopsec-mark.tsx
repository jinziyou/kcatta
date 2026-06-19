import { useId } from "react";

/**
 * loopsec 品牌字形 —— 莫比乌斯无尽环 ∞：左瓣红→紫、右瓣蓝→紫，中心融合为紫色结点。
 * 「循环把红蓝两队融合成紫」的持续安全闭环。颜色固定（深浅背景皆可读），不随文字色变化。
 * 渐变 id 经 useId 命名，避免同页多实例冲突。
 */
export function LoopsecMark({ className }: { className?: string }) {
  const uid = useId().replace(/:/g, "");
  const gL = `${uid}-gL`;
  const gR = `${uid}-gR`;
  return (
    <svg
      viewBox="0 0 64 64"
      className={className}
      role="img"
      aria-label="loopsec"
      fill="none"
    >
      <defs>
        <linearGradient id={gL} x1="6" y1="32" x2="32" y2="32" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#b23a3a" />
          <stop offset="1" stopColor="#5b49a6" />
        </linearGradient>
        <linearGradient id={gR} x1="58" y1="32" x2="32" y2="32" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#2c5fa8" />
          <stop offset="1" stopColor="#5b49a6" />
        </linearGradient>
      </defs>
      <g strokeWidth="6" strokeLinecap="round">
        <path d="M32 32 C25.5 18.5 6 18 6 32 C6 46 25.5 45.5 32 32" stroke={`url(#${gL})`} />
        <path d="M32 32 C38.5 45.5 58 46 58 32 C58 18 38.5 18.5 32 32" stroke={`url(#${gR})`} />
      </g>
      <circle cx="32" cy="32" r="4.6" fill="#5b49a6" />
    </svg>
  );
}
