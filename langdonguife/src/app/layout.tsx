import type { Metadata } from "next";
import { Roboto } from "next/font/google";
import "./globals.css";
import Link from "next/link";
import { AppRouterCacheProvider } from "@mui/material-nextjs/v15-appRouter";
import { ThemeProvider } from "@mui/material/styles";
import theme from "@/theme";
import ToastProvider from "@/providers/ToastProvider";

const roboto = Roboto({
  variable: "--font-roboto",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "Langdon GUI",
  description: "GUI for Langdon",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className={`${roboto.variable} antialiased`}>
        <AppRouterCacheProvider>
          <ThemeProvider theme={theme}>
            <header className="bg-primary flex flex-row items-center p-4 gap-6 sticky w-full z-50">
              <Link href="/">
                <h1>Langdon GUI</h1>
              </Link>
              <div className="flex flex-row gap-4">
                <Link href="/domains">Domains</Link>
                <Link href="/ports">Ports</Link>
                <Link href="/content">Web Content</Link>
                <Link href="/technologies">Technologies</Link>
                <Link href="/vulnerabilities">Vulnerabilities</Link>
                <Link href="/headers">Headers</Link>
                <Link href="/cookies">Cookies</Link>
                <Link href="/apps">Android Apps</Link>
              </div>
            </header>
            <main className="p-12">
              <ToastProvider>{children}</ToastProvider>
            </main>
          </ThemeProvider>
        </AppRouterCacheProvider>
      </body>
    </html>
  );
}
