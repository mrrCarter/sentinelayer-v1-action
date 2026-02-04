import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { GateStatus } from "@/components/dashboard/GateStatus";

describe("GateStatus", () => {
  it("renders passed status", () => {
    render(<GateStatus status="passed" />);
    expect(screen.getByText("Passed")).toBeInTheDocument();
  });

  it("renders blocked status", () => {
    render(<GateStatus status="blocked" />);
    expect(screen.getByText("Blocked")).toBeInTheDocument();
  });
});
