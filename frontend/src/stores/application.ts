import { useAuthStore } from './auth'

type AppStatus = 'active' | 'inactive'

export type CreateRequest = {
  name: string
  company_name: string
  addresses: string[]
  emails: string[]
  phone_numbers: string[]
}

export type UpdateRequest = {
  name: string
  company_name: string
  addresses: string[]
  emails: string[]
  phone_numbers: string[]
}

export interface Application {
  id: string
  version: number
  status: AppStatus
  created_at: number
  created_by: string
  updated_at: number
  updated_by: string
  name: string
  company_name: string
  addresses: string[]
  emails: string[]
  phone_numbers: string[]
}

type KeyStatus = 'active' | 'revoked'

export interface APIKey {
  id: string
  version: number
  application_id: string
  scopes: string[]
  status: KeyStatus
  created_at: number
  created_by: string
  updated_at: number
  updated_by: string
}

interface AppList {
  total: number
  apps: Application[]
}

interface ApiKeyRecord {
  api_key: APIKey
  application: Application
}

interface ApiKeyList {
  total: number
  keys: APIKey[]
}

async function get(id: string): Promise<Application> {
  const auth = useAuthStore()
  if (!auth.token) {
    throw new Error('unauthorized')
  }
  const response = await fetch(`/api/applications/${id}`, {
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

async function create(params: CreateRequest): Promise<Application> {
  const auth = useAuthStore()
  if (!auth.token) {
    throw new Error('unauthorized')
  }
  const response = await fetch('/api/applications', {
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

async function update(id: string, params: UpdateRequest): Promise<void> {
  const auth = useAuthStore()
  if (!auth.token) {
    throw new Error('unauthorized')
  }
  const response = await fetch(`/api/applications/${id}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${auth.token}`,
    },
    body: JSON.stringify(params),
  })
  if (!response.ok) {
    throw new Error(`update failed: ${response.status} ${response.statusText}`)
  }
}

async function list(offset: number, limit: number): Promise<AppList> {
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

  const response = await fetch('/api/applications' + queryString, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${auth.token}`,
    },
  })
  if (!response.ok) {
    throw new Error(`list failed: ${response.status} ${response.statusText}`)
  }
  const { total, apps } = await response.json()
  return { total, apps }
}

async function updateStatus(id: string, status: AppStatus): Promise<void> {
  const auth = useAuthStore()
  if (!auth.token) {
    throw new Error('unauthorized')
  }
  const response = await fetch(`/api/applications/${id}/status`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${auth.token}`,
    },
    body: JSON.stringify({ status }),
  })
  if (!response.ok) {
    throw new Error(`activate failed: ${response.status} ${response.statusText}`)
  }
}

async function createApiKey(appId: string, scopes: string[] = ['all']): Promise<string> {
  const auth = useAuthStore()
  if (!auth.token) {
    throw new Error('unauthorized')
  }
  const response = await fetch(`/api/applications/${appId}/api_keys`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${auth.token}`,
    },
    body: JSON.stringify({ scopes }),
  })
  if (!response.ok) {
    throw new Error(`create failed: ${response.status} ${response.statusText}`)
  }
  const { api_key } = await response.json()
  return api_key
}

async function revokeApiKey(appId: string, id: string): Promise<void> {
  const auth = useAuthStore()
  if (!auth.token) {
    throw new Error('unauthorized')
  }
  const response = await fetch(`/api/applications/${appId}/api_keys/${id}`, {
    method: 'DELETE',
    headers: {
      Authorization: `Bearer ${auth.token}`,
    },
  })
  if (!response.ok) {
    throw new Error(`revoke failed: ${response.status} ${response.statusText}`)
  }
}

async function listApiKeys(appId: string, offset: number, limit: number): Promise<ApiKeyList> {
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

  const response = await fetch(`/api/applications/${appId}/api_keys` + queryString, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${auth.token}`,
    },
  })
  if (!response.ok) {
    throw new Error(`list failed: ${response.status} ${response.statusText}`)
  }
  const { total, keys } = await response.json()
  const api_keys = keys.map((k: ApiKeyRecord) => {
    return k.api_key
  })

  return { total, keys: api_keys }
}

export function useAppStore(): {
  get: (id: string) => Promise<Application>
  create: (params: CreateRequest) => Promise<Application>
  update: (id: string, params: UpdateRequest) => Promise<void>
  list: (offset: number, limit: number) => Promise<AppList>
  updateStatus: (id: string, status: AppStatus) => Promise<void>
  createApiKey: (appId: string) => Promise<string>
  revokeApiKey: (appId: string, id: string) => Promise<void>
  listApiKeys: (appId: string, offset: number, limit: number) => Promise<ApiKeyList>
} {
  return {
    get,
    create,
    update,
    list,
    updateStatus,
    createApiKey,
    revokeApiKey,
    listApiKeys,
  }
}
