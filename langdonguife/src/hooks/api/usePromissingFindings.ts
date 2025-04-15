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
  const [page, setPage] = useState<number | null>(0);
  const [nextPage, setNextPage] = useState<number | null>(null);
  const toastContext = useContext(ToastContext);
  const observedElementRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    async function fetchOverview() {
      try {
        const data = await getPromissingFindings({ page: page! });
        setPromissingFindings((prevState) => [...prevState, ...data.results]);
        setNextPage(data.next);
      } catch (error) {
        toastContext.setToastMessage(String(error));
      }
    }

    if (page !== null) {
      fetchOverview();
    }
  }, [page]);

  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        if (entries[0].isIntersecting) {
          setPage(nextPage);
        }
      },
      { threshold: 1 }
    );

    const currentElement = observedElementRef.current;

    if (currentElement) {
      observer.observe(currentElement);
    }

    return () => {
      if (currentElement) {
        observer.unobserve(currentElement);
      }
    };
  }, [observedElementRef, nextPage]);

  return {
    promissingFindings,
    observedElementRef,
  };
}
