export interface IpAddress {
  id: number;
  address: string;
}

interface Domain {
  id: number;
  name: string;
}

export interface WebDirectory {
  id: number;
  path: string;
  ip_address: IpAddress | null;
  domain: Domain | null;
  uses_ssl: boolean;
}
