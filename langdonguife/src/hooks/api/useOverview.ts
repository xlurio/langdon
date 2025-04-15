import { useState, useEffect, useContext } from "react";
import { getOverview, OverviewResponse } from "@/adapters/overview";
import { ToastContext } from "@/contexts/toastContext";

interface UseOverviewReturn {
  isLoading: boolean;
  overview: OverviewResponse | null;
}

export default function useOverview() {
  const [overview, setOverview] = useState<OverviewResponse | null>(null);
  const toastContext = useContext(ToastContext);

  useEffect(() => {
    async function fetchOverview() {
      try {
        const data = await getOverview();
        setOverview(data);
      } catch (error) {
        toastContext.setToastMessage(String(error));
      }
    }
    fetchOverview();
  }, []);

  return {
    isLoading: !overview,
    overview,
  };
}
