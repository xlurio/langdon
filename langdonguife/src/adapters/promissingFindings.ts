export interface PromissingFindingsResult {
  id: number;
  label: string;
  type: "web_directory" | "used_port" | "technology" | "vulnerability";
}

interface PromissingFindingsResponse {
  next: number;
  results: PromissingFindingsResult[];
}

interface GetPromissingFindingsParams {
  page?: number;
}

export default async function getPromissingFindings({
  page,
}: GetPromissingFindingsParams): Promise<PromissingFindingsResponse> {
  const cleanedPage = page ? page : 0;

  return {
    next: cleanedPage + 1,
    results: [
      {
        id: Math.floor(Math.random() * 1000000),
        label: "hxxps://example.com",
        type: "web_directory",
      },
      {
        id: Math.floor(Math.random() * 1000000),
        label: "192[.]168[.]0[.]1:8080",
        type: "used_port",
      },
      {
        id: Math.floor(Math.random() * 1000000),
        label: "Apache HTTP Server 2.4.18",
        type: "technology",
      },
      {
        id: Math.floor(Math.random() * 1000000),
        label: "CVE-2025-0868",
        type: "vulnerability",
      },
    ],
  };
}
