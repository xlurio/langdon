"use client";
import useTechnology from "@/hooks/api/useTechnology";
import { Skeleton } from "@mui/material";
import { lazy, Suspense } from "react";

const TechnologyDetailData = lazy(
  () => import("@/components/technologies/TechnologyDetailData")
);

function LoadingTechnologyDetailPage() {
  return (
    <div>
      <Skeleton height={96} width={96} />
    </div>
  );
}

interface TechnologyDetailProps {
  technologyId: number;
}

export default function TechnologyDetail({
  technologyId,
}: TechnologyDetailProps) {
  const technologyQuery = useTechnology({
    id: technologyId,
  });

  return technologyQuery.isLoading ? (
    <LoadingTechnologyDetailPage />
  ) : (
    <Suspense fallback={<LoadingTechnologyDetailPage />}>
      <TechnologyDetailData data={technologyQuery.technology!} />
    </Suspense>
  );
}
