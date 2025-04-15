import Overview from "@/components/home/Overview";
import PromissingFindings from "@/components/home/PromissingFindings";

export default function Home() {
  return (
    <div className="flex flex-col gap-10">
      <Overview />
      <PromissingFindings />
    </div>
  );
}
