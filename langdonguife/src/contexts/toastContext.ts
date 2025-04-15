"use client";
import { createContext, Dispatch, SetStateAction } from "react";

interface ToastContextType {
  toastMessage: string | null;
  setToastMessage: Dispatch<SetStateAction<string | null>>;
}

const ToastContext = createContext<ToastContextType>({
  toastMessage: null,
  setToastMessage: (value: SetStateAction<string | null>) => {},
});

export { ToastContext };
