import { OverviewResponse } from "@/adapters/overview";
import Card from "@/components/containers/Card";
import Link from "next/link";

interface OverviewDataProps {
  data: OverviewResponse;
}

export default function OverviewData({ data }: OverviewDataProps) {
  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-row justify-center gap-6">
        <Link href="/ports">
          <Card className="flex flex-col p-6 text-green-500">
            <span className="text-6xl font-bold">{data.ip_addresses}</span>
            <span>IP addresses found</span>
          </Card>
        </Link>
        <Link href="/content">
          <Card className="flex flex-col p-6 text-orange-500">
            <span className="text-6xl font-bold">{data.web_directories}</span>
            <span>Web pages found</span>
          </Card>
        </Link>
        <Link href="/technologies">
          <Card className="flex flex-col p-6 text-yellow-500">
            <span className="text-6xl font-bold">{data.technologies}</span>
            <span>Technologies found</span>
          </Card>
        </Link>
        <Link href="/vulnerabilities">
          <Card className="flex flex-col p-6 text-red-500">
            <span className="text-6xl font-bold">{data.vulnerabilities}</span>
            <span>Vulnerabilites found</span>
          </Card>
        </Link>
        <Link href="/ports">
          <Card className="flex flex-col p-6 text-teal-500">
            <span className="text-6xl font-bold">{data.used_ports}</span>
            <span>Ports found</span>
          </Card>
        </Link>
      </div>
      <div className="flex flex-row justify-center gap-6">
        <Link href="/domains">
          <Card className="flex flex-col p-6 text-blue-500">
            <span className="text-6xl font-bold">{data.domains}</span>
            <span>Domains found</span>
          </Card>
        </Link>
        <Link href="/headers">
          <Card className="flex flex-col p-6 text-indigo-500">
            <span className="text-6xl font-bold">{data.http_headers}</span>
            <span>Headers found</span>
          </Card>
        </Link>
        <Link href="/cookies">
          <Card className="flex flex-col p-6 text-purple-500">
            <span className="text-6xl font-bold">{data.http_cookies}</span>
            <span>Cookies found</span>
          </Card>
        </Link>
        <Link href="/apps">
          <Card className="flex flex-col p-6 text-rose-500">
            <span className="text-6xl font-bold">{data.android_apps}</span>
            <span>Android apps found</span>
          </Card>
        </Link>
      </div>
    </div>
  );
}
