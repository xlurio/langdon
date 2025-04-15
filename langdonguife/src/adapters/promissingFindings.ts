export interface PromissingFindingsResult {
  id: number;
  label: string;
  type:  "domain" | "technology" | "used_port" | "vulnerability" | "web_directory";
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
  const response = await fetch(`/api/promissingfindings?page=${page}`);

  return response.json();
}
