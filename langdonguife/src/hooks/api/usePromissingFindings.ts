"use client";
import { useState, useEffect, useContext, useRef, RefObject } from "react";
import { ToastContext } from "@/contexts/toastContext";
import getPromissingFindings, {
  PromissingFindingsResult,
} from "@/adapters/promissingFindings";

interface UsePromissingFindingsReturn {
  promissingFindings: PromissingFindingsResult[];
  observedElementRef: RefObject<HTMLElement | null>;
}

export default function usePromissingFindings(): UsePromissingFindingsReturn {
  const [promissingFindings, setPromissingFindings] = useState<
    PromissingFindingsResult[]
  >([]);
  const [page, setPage] = useState<number>(0);
  const toastContext = useContext(ToastContext);
  const observedElementRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    async function fetchOverview() {
      try {
        const data = await getPromissingFindings({ page });
        setPromissingFindings((prevState) => [...prevState, ...data.results]);
      } catch (error) {
        toastContext.setToastMessage(String(error));
      }
    }
    fetchOverview();
  }, [page]);

  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        if (entries[0].isIntersecting) {
          setPage((prevPage) => prevPage + 1);
        }
      },
      { threshold: 1 }
    );

    if (observedElementRef.current) {
      observer.observe(observedElementRef.current);
    }

    return () => {
      if (observedElementRef.current) {
        observer.unobserve(observedElementRef.current);
      }
    };
  }, [observedElementRef]);

  return {
    promissingFindings,
    observedElementRef,
  };
}
