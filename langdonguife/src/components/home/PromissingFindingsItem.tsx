import Link from "next/link";
import { PromissingFindingsResult } from "@/adapters/promissingFindings";

interface PromissingFindingsItemProps {
  data: PromissingFindingsResult;
}

function getUrlFromPromissingFindingData({
  data,
}: PromissingFindingsItemProps) {
  switch (data.type) {
    case "domain":
      return `/domains?domainId=${data.id}`;
    case "technology":
      return `/technologies?technologyId=${data.id}`;
    case "used_port":
      return `/ports?portId=${data.id}`;
    case "vulnerability":
      return `/vulnerabilities?vulnerabilityId=${data.id}`;
    case "web_directory":
      return `/content?contentId=${data.id}`;
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
