import { Link } from "react-router-dom";
import { GateStatus } from "@/components/dashboard/GateStatus";
import { FindingsBadge } from "@/components/dashboard/FindingsBadge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { formatDuration, formatRelativeTime } from "@/lib/format";
import type { Run } from "@/types/run";

export function RunsTable({ runs }: { runs: Run[] }) {
  if (!runs.length) {
    return (
      <div className="rounded-2xl border border-dashed border-border/70 p-6 text-center text-sm text-muted-foreground">
        No runs yet.
      </div>
    );
  }

  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Run</TableHead>
          <TableHead>Repo</TableHead>
          <TableHead>Status</TableHead>
          <TableHead>Findings</TableHead>
          <TableHead>Duration</TableHead>
          <TableHead>When</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {runs.map((run) => (
          <TableRow key={run.id}>
            <TableCell>
              <Link
                to={`/dashboard/runs/${run.id}`}
                className="font-mono text-xs text-primary hover:underline"
              >
                {run.id.slice(0, 8)}
              </Link>
            </TableCell>
            <TableCell className="font-medium">
              {run.repo_owner}/{run.repo_name}
            </TableCell>
            <TableCell>
              <GateStatus status={run.status} size="sm" />
            </TableCell>
            <TableCell>
              <FindingsBadge findings={run.findings} compact />
            </TableCell>
            <TableCell>{formatDuration(run.duration_ms)}</TableCell>
            <TableCell className="text-muted-foreground">
              {formatRelativeTime(run.timestamp)}
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
