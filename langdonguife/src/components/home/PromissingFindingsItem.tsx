import Link from "next/link";
import { PromissingFindingsResult } from "@/adapters/promissingFindings";

interface PromissingFindingsItemProps {
  data: PromissingFindingsResult;
}

function getUrlFromPromissingFindingData({
  data,
}: PromissingFindingsItemProps) {
  switch (data.type) {
    case "web_directory":
      return `/content/${data.id}`;
    case "used_port":
      return `/ports/${data.id}`;
    case "technology":
      return `/technologies/${data.id}`;
    case "vulnerability":
      return `/vulnerabilities/${data.id}`;
    default:
      return "#";
  }
}

export default function PromissingFindingsItem({
  data,
}: PromissingFindingsItemProps) {
  return (
    <Link href={getUrlFromPromissingFindingData({ data })}>
      <li className="bg-background p-6 rounded-lg">{data.label}</li>
    </Link>
  );
}
