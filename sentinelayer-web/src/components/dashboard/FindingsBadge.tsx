import { Badge } from "@/components/ui/badge";
import type { RepoFindingsCount } from "@/types/repo";

interface FindingsBadgeProps {
  findings: RepoFindingsCount;
  compact?: boolean;
}

export function FindingsBadge({ findings, compact }: FindingsBadgeProps) {
  return (
    <div className="flex flex-wrap items-center gap-2">
      {findings.P0 > 0 && (
        <Badge variant="destructive" className="gap-1">
          <span className="font-mono">{findings.P0}</span>
          {!compact && <span>P0</span>}
        </Badge>
      )}
      {findings.P1 > 0 && (
        <Badge variant="warning" className="gap-1">
          <span className="font-mono">{findings.P1}</span>
          {!compact && <span>P1</span>}
        </Badge>
      )}
      {findings.P2 > 0 && (
        <Badge variant="secondary" className="gap-1">
          <span className="font-mono">{findings.P2}</span>
          {!compact && <span>P2</span>}
        </Badge>
      )}
      {findings.P3 > 0 && (
        <Badge variant="outline" className="gap-1">
          <span className="font-mono">{findings.P3}</span>
          {!compact && <span>P3</span>}
        </Badge>
      )}
      {Object.values(findings).every((value) => value === 0) && (
        <Badge variant="success">Clean</Badge>
      )}
    </div>
  );
}
