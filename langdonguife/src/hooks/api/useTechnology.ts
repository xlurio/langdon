import { useState, useEffect, useContext } from "react";
import { getTechnologyById, TechnologyResponse } from "@/adapters/technologies";
import { ToastContext } from "@/contexts/toastContext";

interface UseTechnologyParams {
  id: number;
}

interface UseTechnologyReturn {
  isLoading: boolean;
  technology: TechnologyResponse | null;
}

export default function useTechnology({
  id,
}: UseTechnologyParams): UseTechnologyReturn {
  const [technology, setTechnology] = useState<TechnologyResponse | null>(null);
  const toastContext = useContext(ToastContext);

  useEffect(() => {
    async function fetchTechnology() {
      try {
        const data = await getTechnologyById({ id: id! });
        setTechnology(data);
      } catch (error) {
        toastContext.setToastMessage(String(error));
      }
    }
    fetchTechnology();
  }, []);

  return {
    isLoading: !technology,
    technology,
  };
}
