export interface OverviewResponse {
  android_apps: number;
  domains: number;
  http_cookies: number;
  http_headers: number;
  ip_addresses: number;
  technologies: number;
  used_ports: number;
  vulnerabilities: number;
  web_directories: number;
}

export async function getOverview(): Promise<OverviewResponse> {
  const response = await fetch("/api/overview");
  return response.json();
}
