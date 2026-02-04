import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { RunTrendPoint } from "@/types/run";

const colors = {
  P0: "#E11D48",
  P1: "#F59E0B",
  P2: "#64748B",
  P3: "#0EA5A4",
};

export function TrendChart({ data }: { data: RunTrendPoint[] }) {
  return (
    <div className="h-64 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data} margin={{ top: 10, right: 20, left: 0, bottom: 0 }}>
          <defs>
            {Object.entries(colors).map(([key, value]) => (
              <linearGradient key={key} id={`color-${key}`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={value} stopOpacity={0.35} />
                <stop offset="95%" stopColor={value} stopOpacity={0} />
              </linearGradient>
            ))}
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
          <XAxis dataKey="date" tickLine={false} axisLine={false} fontSize={12} />
          <YAxis tickLine={false} axisLine={false} fontSize={12} width={32} />
          <Tooltip
            contentStyle={{
              borderRadius: 16,
              border: "1px solid #e2e8f0",
              boxShadow: "0 10px 30px rgba(15, 23, 42, 0.12)",
            }}
          />
          {Object.keys(colors).map((key) => (
            <Area
              key={key}
              type="monotone"
              dataKey={key}
              stackId="1"
              stroke={colors[key as keyof typeof colors]}
              fill={`url(#color-${key})`}
              strokeWidth={2}
              dot={false}
              activeDot={{ r: 4 }}
            />
          ))}
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
