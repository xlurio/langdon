"use client";
import Card from "@/components/containers/Card";
import Skeleton from "@mui/material/Skeleton";
import usePromissingFindings from "@/hooks/api/usePromissingFindings";
import { lazy, Suspense } from "react";

const PromissingFindingsItem = lazy(() => import("./PromissingFindingsItem"));

export default function PromissingFindings() {
  const promissingFindingsQuery = usePromissingFindings();

  return (
    <Card className="flex flex-col p-6 gap-6">
      <h2>Promissing Findings</h2>
      <ul className="flex flex-col gap-3">
        <Suspense
          fallback={
            <Skeleton
              height={114}
              sx={{ marginTop: "calc(var(--spacing) * -6)" }}
              component="li"
            />
          }
        >
          {promissingFindingsQuery.promissingFindings.map((data) => (
            <PromissingFindingsItem
              key={`${data.type}_${data.id}`}
              data={data}
            />
          ))}
        </Suspense>
        <Skeleton
          height={114}
          sx={{ marginTop: "calc(var(--spacing) * -6)" }}
          component="li"
          ref={
            promissingFindingsQuery.observedElementRef as React.RefObject<HTMLLIElement>
          }
        />
      </ul>
    </Card>
  );
}
