"use client";
import { lazy, Suspense, useEffect, useState } from "react";

const TechnologyDetail = lazy(
  () => import("@/components/technologies/TechnologyDetail")
);

export default function TechnologyDetailPage() {
  const [isDetailPage, setIsDetailPage] = useState<boolean | null>(null);
  const [technologyId, setTechnologyId] = useState<number | null>(null);

  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const technologyId = urlParams.get("technologyId");

    if (technologyId) {
      setTechnologyId(Number.parseInt(technologyId));
      setIsDetailPage(true);
    } else {
      setIsDetailPage(false);
    }
  }, []);

  return (
    isDetailPage && (
      <Suspense>
        <TechnologyDetail technologyId={technologyId!} />
      </Suspense>
    )
  );
}
