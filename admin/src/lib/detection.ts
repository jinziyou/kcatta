import type {
  CoverageStatus,
  DetectionCoverage as DetectionCoverageRow,
  DetectionResult,
  DetectionStatus,
  DetectorKind,
} from "@/lib/contracts";

export interface DetectionCoverage {
  status: DetectionStatus | "unknown";
  reason: string | null;
  scannedPackages: number;
  unresolvedPackages: number;
  uncoveredPackages: number;
  truncated: boolean;
  truncationReason: string | null;
}

/** Normalize new coverage fields while treating pre-upgrade records conservatively. */
export function detectionCoverage(result: DetectionResult): DetectionCoverage {
  return {
    status: result.detection_status ?? "unknown",
    reason: result.status_reason ?? null,
    scannedPackages: result.scanned_package_count ?? 0,
    unresolvedPackages: result.unresolved_package_count ?? 0,
    uncoveredPackages: result.uncovered_package_count ?? 0,
    truncated: result.truncated ?? false,
    truncationReason: result.truncation_reason ?? null,
  };
}

export function detectionRecordComplete(result: DetectionResult): boolean {
  const coverage = detectionCoverage(result);
  const matrix = result.coverage ?? [];
  return (
    coverage.status === "complete" &&
    !coverage.truncated &&
    matrix.length > 0 &&
    matrix.every((row) => row.status === "complete" || row.status === "disabled")
  );
}

export const DETECTOR_LABEL: Record<DetectorKind, string> = {
  osv: "OSV/CVE",
  debian_tracker: "Debian 漏洞跟踪",
  defender: "Microsoft Defender",
  malware: "恶意文件",
  posture: "安全基线",
  secret: "密钥泄露",
};

export const COVERAGE_STATUS_LABEL: Record<CoverageStatus, string> = {
  complete: "已完成",
  partial: "部分覆盖",
  disabled: "未启用",
  failed: "失败",
  unknown: "未知",
};

const COVERAGE_RANK: Record<CoverageStatus, number> = {
  complete: 0,
  disabled: 1,
  unknown: 2,
  partial: 3,
  failed: 4,
};

/** Merge child-chunk matrices into one logical report matrix. */
export function mergeDetectionCoverage(results: DetectionResult[]): DetectionCoverageRow[] {
  const merged = new Map<string, DetectionCoverageRow>();
  for (const result of results) {
    for (const row of result.coverage ?? []) {
      const key = `${row.detector}\u0000${row.ecosystem ?? ""}`;
      const current = merged.get(key);
      if (!current) {
        merged.set(key, { ...row });
        continue;
      }
      current.scanned_count = (current.scanned_count ?? 0) + (row.scanned_count ?? 0);
      current.skipped_count = (current.skipped_count ?? 0) + (row.skipped_count ?? 0);
      current.finding_count = (current.finding_count ?? 0) + (row.finding_count ?? 0);
      if (COVERAGE_RANK[row.status] > COVERAGE_RANK[current.status]) {
        current.status = row.status;
      }
      const reasons = new Set([current.reason, row.reason].filter(Boolean));
      current.reason = reasons.size > 0 ? [...reasons].join(", ") : null;
    }
  }
  return [...merged.values()].sort(
    (a, b) =>
      a.detector.localeCompare(b.detector) ||
      (a.ecosystem ?? "").localeCompare(b.ecosystem ?? ""),
  );
}

export const DETECTION_STATUS_LABEL: Record<DetectionCoverage["status"], string> = {
  complete: "软件包漏洞检测完成",
  partial: "软件包漏洞检测不完整",
  disabled: "软件包漏洞检测未启用",
  failed: "软件包漏洞检测失败",
  unknown: "历史记录：软件包漏洞检测状态未知",
};

const REASON_LABEL: Record<string, string> = {
  legacy_coverage_unknown: "历史记录未保存 OSV 匹配覆盖信息",
  no_package_inventory: "报告没有可供 OSV 匹配的软件包清单",
  osv_store_empty: "本地 OSV 漏洞库为空",
  osv_sync_incomplete: "OSV 漏洞库同步不完整",
  osv_ecosystem_unsupported: "OSV 不支持该软件包生态（Windows 软件漏洞需接入 MDVM）",
  some_osv_ecosystems_unsupported:
    "部分软件包生态不受 OSV 支持（Windows 软件漏洞需接入 MDVM）",
  osv_ecosystem_not_synced: "软件包所属生态尚未同步到 OSV 漏洞库",
  some_osv_ecosystems_not_synced: "部分软件包生态尚未同步到 OSV 漏洞库",
  ecosystem_unresolved: "无法解析软件包生态",
  some_package_ecosystems_unresolved: "部分软件包无法解析生态",
  osv_detection_failed: "OSV 匹配执行失败",
  debian_tracker_empty: "Debian Security Tracker 本地索引为空",
  debian_tracker_stale: "Debian Security Tracker 本地索引已过期，结果仅作部分覆盖",
  debian_tracker_advisory_undetermined: "部分 Debian 漏洞状态尚未确定",
  kali_package_origin_unverified: "Kali 软件包来源版本无法与 Debian 仓库精确核验",
  some_kali_package_origins_unverified: "部分 Kali 软件包来源版本无法与 Debian 仓库精确核验",
  debian_tracker_max_findings: "Debian Tracker 发现数量达到安全上限",
  debian_tracker_max_bytes: "Debian Tracker 发现结果大小达到安全上限",
  max_findings: "发现项数量达到安全上限",
  max_bytes: "发现结果大小达到安全上限",
  max_records: "派生记录数量达到安全上限",
  limit_reached: "发现生成达到安全上限",
  osv_max_findings: "OSV 发现数量达到安全上限",
  osv_max_bytes: "OSV 发现结果大小达到安全上限",
  scanner_max_findings: "扫描器发现数量达到安全上限",
  scanner_max_bytes: "扫描器发现结果大小达到安全上限",
  combined_max_findings: "合并后发现数量达到安全上限",
  combined_max_bytes: "合并后发现结果大小达到安全上限",
  producer_detector_coverage_unknown: "旧版采集器未上报该检测器是否运行",
  detector_not_enabled: "本次任务未启用该检测器",
  detector_finding_count_mismatch: "检测器声明的发现数量与实际上传不一致",
  defender_unavailable: "Microsoft Defender 不可用或无法读取状态",
  defender_scan_failed: "Microsoft Defender 按需扫描失败，现有遥测仍已上报",
  defender_telemetry_partial: "Microsoft Defender 部分状态、历史或事件日志无法读取",
  defender_collection_failed: "Microsoft Defender 本机采集失败",
  defender_artifact_invalid: "Microsoft Defender 采集结果格式无效",
  coverage_matrix_grouped: "生态数量过多，剩余生态已合并展示",
};

export function detectionReasonLabel(reason: string): string {
  return reason
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean)
    .map((part) => REASON_LABEL[part] ?? part)
    .join("；");
}
