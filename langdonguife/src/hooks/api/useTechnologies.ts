"use client";
import { useState, useEffect, useContext, useRef, RefObject } from "react";
import { ToastContext } from "@/contexts/toastContext";
import { getTechnologies, TechnologiesResult } from "@/adapters/technologies";

interface UseTechnologiesReturn {
  promissingFindings: TechnologiesResult[];
  observedElementRef: RefObject<HTMLElement | null>;
}

export default function useTechnologies(): UseTechnologiesReturn {
  const [promissingFindings, setTechnologies] = useState<TechnologiesResult[]>(
    []
  );
  const [page, setPage] = useState<number | null>(0);
  const [nextPage, setNextPage] = useState<number | null>(null);
  const toastContext = useContext(ToastContext);
  const observedElementRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    async function fetchOverview() {
      try {
        const data = await getTechnologies({ page: page! });
        setTechnologies((prevState) => [...prevState, ...data.results]);
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
