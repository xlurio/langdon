import { WebDirectory } from "@/types/api";

export function getFullUrlFromDirectory({
  web_directory,
}: {
  web_directory: WebDirectory;
}) {
  const schema = web_directory.uses_ssl ? "https" : "http";
  const hostname = web_directory.domain
    ? web_directory.domain.name
    : web_directory.ip_address!.address;
  const path = web_directory.path.startsWith("/")
    ? web_directory.path.slice(1)
    : web_directory.path;

  return `${schema}://${hostname}/${path}`;
}
