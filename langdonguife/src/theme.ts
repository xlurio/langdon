"use client";
import { createTheme } from "@mui/material/styles";

const theme = createTheme({
  typography: {
    fontFamily: "var(--font-roboto)",
  },
  palette: {
    primary: {
      main: "#A855F7",
      contrastText: "#fff",
    },
    background: {
      default: "#1e2939",
    },
    text: {
      primary: "#fff",
      secondary: "#000",
    },
  },
});

export default theme;
