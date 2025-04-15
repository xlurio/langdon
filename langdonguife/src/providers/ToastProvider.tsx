"use client";
import { ToastContext } from "@/contexts/toastContext";
import { useState } from "react";
import Snackbar from "@mui/material/Snackbar";

export default function ToastProvider({
  children,
}: {
  children: React.ReactNode;
}) {
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  function handleClose() {
    setToastMessage(null);
  }

  return (
    <ToastContext.Provider value={{ toastMessage, setToastMessage }}>
      <Snackbar
        open={!!toastMessage}
        autoHideDuration={6000}
        onClose={handleClose}
        message={toastMessage}
      />
      {children}
    </ToastContext.Provider>
  );
}
