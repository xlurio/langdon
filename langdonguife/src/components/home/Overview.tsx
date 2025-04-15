"use client";
import { lazy, Suspense } from "react";
import { Skeleton } from "@mui/material";
import useOverview from "@/hooks/api/useOverview";

const OverviewData = lazy(() => import("./OverviewData"));

function LoadingOverview() {
  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-row justify-center gap-6">
        <Skeleton
          height={220}
          width={185}
          sx={{ marginTop: "calc(var(--spacing) * -12)" }}
        />
        <Skeleton
          height={220}
          width={185}
          sx={{ marginTop: "calc(var(--spacing) * -12)" }}
        />
        <Skeleton
          height={220}
          width={185}
          sx={{ marginTop: "calc(var(--spacing) * -12)" }}
        />
        <Skeleton
          height={220}
          width={185}
          sx={{ marginTop: "calc(var(--spacing) * -12)" }}
        />
        <Skeleton
          height={220}
          width={185}
          sx={{ marginTop: "calc(var(--spacing) * -12)" }}
        />
      </div>
      <div className="flex flex-row justify-center gap-6">
        <Skeleton
          height={220}
          width={185}
          sx={{
            marginTop: "calc(var(--spacing) * -22)",
            marginBottom: "calc(var(--spacing) * -10)",
          }}
        />
        <Skeleton
          height={220}
          width={185}
          sx={{
            marginTop: "calc(var(--spacing) * -22)",
            marginBottom: "calc(var(--spacing) * -10)",
          }}
        />
        <Skeleton
          height={220}
          width={185}
          sx={{
            marginTop: "calc(var(--spacing) * -22)",
            marginBottom: "calc(var(--spacing) * -10)",
          }}
        />
        <Skeleton
          height={220}
          width={185}
          sx={{
            marginTop: "calc(var(--spacing) * -22)",
            marginBottom: "calc(var(--spacing) * -10)",
          }}
        />
      </div>
    </div>
  );
}

export default function Overview() {
  const overviewQuery = useOverview();

  return overviewQuery.isLoading ? (
    <LoadingOverview />
  ) : (
    <Suspense fallback={<LoadingOverview />}>
      <OverviewData data={overviewQuery.overview!} />
    </Suspense>
  );
}
