import Card from "@/components/containers/Card";
import Overview from "@/components/home/Overview";
import PromissingFindings from "@/components/home/PromissingFindings";
import Skeleton from "@mui/material/Skeleton";
import Link from "next/link";

export default function Home() {
  return (
    <div className="flex flex-col gap-10">
      <Overview />
      <PromissingFindings />
    </div>
  );
}
