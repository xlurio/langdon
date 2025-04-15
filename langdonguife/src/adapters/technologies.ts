import { IpAddress, WebDirectory } from "@/types/api";

interface GetTechnologyByIdParams {
  id: number;
}

interface UsedPort {
  id: number;
  port: number;
  ip_address: IpAddress;
}

interface Vulnerability {
  id: number;
  name: string;
}

export interface TechnologyResponse {
  id: number;
  name: string;
  version: string;
  used_ports: UsedPort[];
  web_directories: WebDirectory[];
  vulnerabilities: Vulnerability[];
}

interface GetTechnologiesParams {
  page?: number;
}

export interface TechnologiesResult {
  id: number;
  name: string;
  version: string;
}

export interface TechnologiesResponse {
  count: number;
  next: number | null;
  results: TechnologiesResult[];
}

export async function getTechnologies({
  page,
}: GetTechnologiesParams): Promise<TechnologiesResponse> {
  const _cleanedPage = page ? page : 0;

  return {
    count: 100,
    next: null,
    results: [],
  };
}

export async function getTechnologyById({
  id,
}: GetTechnologyByIdParams): Promise<TechnologyResponse> {
  return {
    id,
    name: "Example Technology",
    version: "1.0.0",
    used_ports: [
      {
        id: 1,
        port: 8080,
        ip_address: {
          id: 1,
          address: "192.168.1.1",
        },
      },
      {
        id: 2,
        port: 8080,
        ip_address: {
          id: 1,
          address: "192.168.1.1",
        },
      },
      {
        id: 3,
        port: 8080,
        ip_address: {
          id: 1,
          address: "192.168.1.1",
        },
      },
    ],
    web_directories: [
      {
        id: 1,
        path: "/example",
        domain: {
          id: 1,
          name: "example.com",
        },
        ip_address: null,
        uses_ssl: true,
      },
      {
        id: 2,
        path: "/example",
        domain: {
          id: 1,
          name: "example.com",
        },
        ip_address: null,
        uses_ssl: true,
      },
      {
        id: 3,
        path: "/example",
        domain: {
          id: 1,
          name: "example.com",
        },
        ip_address: null,
        uses_ssl: true,
      },
    ],
    vulnerabilities: [
      {
        id: 1,
        name: "Example Vulnerability",
      },
      {
        id: 2,
        name: "Example Vulnerability",
      },
      {
        id: 3,
        name: "Example Vulnerability",
      },
    ],
  };
}
