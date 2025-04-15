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
  return {
    android_apps: 2367,
    domains: 2367,
    http_cookies: 2367,
    http_headers: 2367,
    ip_addresses: 2367,
    technologies: 2367,
    used_ports: 2367,
    vulnerabilities: 2367,
    web_directories: 2367,
  };
}
