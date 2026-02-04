import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { Finding } from "@/types/run";

const severityMap = {
  P0: "destructive",
  P1: "warning",
  P2: "secondary",
  P3: "outline",
} as const;

export function FindingsTable({ findings }: { findings: Finding[] }) {
  if (!findings.length) {
    return (
      <div className="rounded-2xl border border-dashed border-border/70 p-6 text-center text-sm text-muted-foreground">
        No findings reported.
      </div>
    );
  }

  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Severity</TableHead>
          <TableHead>Issue</TableHead>
          <TableHead>File</TableHead>
          <TableHead>Details</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {findings.map((finding) => (
          <TableRow key={finding.id}>
            <TableCell>
              <Badge variant={severityMap[finding.severity]}>{finding.severity}</Badge>
            </TableCell>
            <TableCell className="font-medium">{finding.title}</TableCell>
            <TableCell className="text-xs text-muted-foreground">
              {finding.file_path ? (
                <span>
                  {finding.file_path}
                  {finding.line_start ? `:${finding.line_start}` : ""}
                </span>
              ) : (
                "-"
              )}
            </TableCell>
            <TableCell className="text-sm text-muted-foreground">
              {finding.description || "-"}
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
