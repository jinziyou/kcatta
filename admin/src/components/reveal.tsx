"use client";

import { Children, useState, type ReactNode } from "react";

import { Button } from "@/components/ui/button";
import { TableCell, TableRow } from "@/components/ui/table";

/**
 * 统一「加载更多」(客户端渐进展开)。数据已按上限取回,这里只控制可见条数,
 * 零后端改动。两种形态:RevealList(卡片网格)与 RevealRows(表格行)。
 */

/** 卡片/网格:渲染网格 + 居中「加载更多」按钮。children 为已渲染的全部条目。 */
export function RevealList({
  children,
  className,
  initial = 12,
  step = 12,
}: {
  children: ReactNode;
  className?: string;
  initial?: number;
  step?: number;
}) {
  const all = Children.toArray(children);
  const [visible, setVisible] = useState(initial);
  const rest = all.length - visible;
  return (
    <>
      <div className={className}>{all.slice(0, visible)}</div>
      {rest > 0 && (
        <div className="flex justify-center pt-1">
          <Button variant="outline" size="sm" onClick={() => setVisible((v) => v + step)}>
            加载更多（剩余 {rest}）
          </Button>
        </div>
      )}
    </>
  );
}

/** 表格:放进 <TableBody> 内,children 为已渲染的全部行,「加载更多」以整行呈现。 */
export function RevealRows({
  children,
  colSpan,
  initial = 20,
  step = 20,
}: {
  children: ReactNode;
  colSpan: number;
  initial?: number;
  step?: number;
}) {
  const all = Children.toArray(children);
  const [visible, setVisible] = useState(initial);
  const rest = all.length - visible;
  return (
    <>
      {all.slice(0, visible)}
      {rest > 0 && (
        <TableRow className="hover:bg-transparent">
          <TableCell colSpan={colSpan} className="py-3 text-center">
            <Button variant="ghost" size="sm" onClick={() => setVisible((v) => v + step)}>
              加载更多（剩余 {rest}）
            </Button>
          </TableCell>
        </TableRow>
      )}
    </>
  );
}
