import { useAuthStore } from './auth'

type CertType = 'ca' | 'business_unit'
type CertStatus = 'active' | 'revoked'

export type CreateRequest = {
  cert: string
  private_key: string
}

export interface Certificate {
  id: string
  version: number
  type: CertType
  status: CertStatus
  created_at: number
  created_by: string
  revoked_at: number
  revoked_by: string
  private_key: string
  certificate: string
  certificate_fingerprint: string
}

interface CertList {
  total: number
  certs: Certificate[]
}

async function list(offset: number, limit: number): Promise<CertList> {
  const auth = useAuthStore()
  if (!auth.token) {
    throw new Error('unauthorized')
  }

  const searchParams: Record<string, any> = new URLSearchParams()
  if (offset > 0) {
    searchParams.append('offset', offset)
  }
  if (limit > 0) {
    searchParams.append('limit', limit)
  }
  const queryString = searchParams.toString() ? `?${searchParams.toString()}` : ''

  const response = await fetch('/api/ca/certificates' + queryString, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${auth.token}`,
    },
  })
  if (!response.ok) {
    throw new Error(`list failed: ${response.status} ${response.statusText}`)
  }
  const { total, certs } = await response.json()
  return { total, certs }
}

async function create(params: CreateRequest): Promise<Certificate> {
  const auth = useAuthStore()
  if (!auth.token) {
    throw new Error('unauthorized')
  }
  const response = await fetch('/api/ca/certificates', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${auth.token}`,
    },
    body: JSON.stringify(params),
  })
  if (!response.ok) {
    throw new Error(`create failed: ${response.status} ${response.statusText}`)
  }
  return response.json()
}

async function get(id: string): Promise<Certificate> {
  const auth = useAuthStore()
  if (!auth.token) {
    throw new Error('unauthorized')
  }
  const response = await fetch(`/api/ca/certificates/${id}`, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${auth.token}`,
    },
  })
  if (!response.ok) {
    throw new Error(`get failed: ${response.status} ${response.statusText}`)
  }
  return response.json()
}

async function revoke(id: string): Promise<void> {
  const auth = useAuthStore()
  if (!auth.token) {
    throw new Error('unauthorized')
  }
  const response = await fetch(`/api/ca/certificates/${id}`, {
    method: 'DELETE',
    headers: {
      Authorization: `Bearer ${auth.token}`,
    },
  })
  if (!response.ok) {
    throw new Error(`revoke failed: ${response.status} ${response.statusText}`)
  }
}

export function useCertStore(): {
  list: (offset: number, limit: number) => Promise<CertList>
  create: (params: CreateRequest) => Promise<Certificate>
  get: (id: string) => Promise<Certificate>
  revoke: (id: string) => Promise<void>
} {
  return {
    list,
    create,
    get,
    revoke,
  }
}
