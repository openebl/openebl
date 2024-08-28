import { useAuthStore } from './auth'

type UserStatus = 'active' | 'inactive'
export interface User {
  id: string
  username: string
  status: UserStatus
  version: number
  name: string
  emails: string[]
  note: string
  created_at: number
  created_by: string
  updated_at: number
  updated_by: string
}

export interface CreateRequest {
  username: string
  password: string
  name: string
  emails: string[]
  note: string
}

export interface UpdateRequest {
  username: string
  name: string
  emails: string[]
  note: string
}

interface UserList {
  total: number
  users: User[]
}

async function create(params: CreateRequest): Promise<void> {
  const auth = useAuthStore()
  if (!auth.token) {
    throw new Error('unauthorized')
  }
  const response = await fetch('/api/users', {
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
}

async function get(id: string): Promise<User> {
  const auth = useAuthStore()
  if (!auth.token) {
    throw new Error('unauthorized')
  }
  const response = await fetch(`/api/users/${id}`, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${auth.token}`,
    },
  })
  if (!response.ok) {
    throw new Error(`get failed: ${response.status} ${response.statusText}`)
  }
  return await response.json()
}

async function update(id: string, params: UpdateRequest): Promise<void> {
  const auth = useAuthStore()
  if (!auth.token) {
    throw new Error('unauthorized')
  }
  const response = await fetch(`/api/users/${id}`, {
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

async function updateStatus(id: string, status: UserStatus): Promise<void> {
  const auth = useAuthStore()
  if (!auth.token) {
    throw new Error('unauthorized')
  }
  const response = await fetch(`/api/users/${id}/status`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${auth.token}`,
    },
    body: JSON.stringify({ status }),
  })
  if (!response.ok) {
    throw new Error(`activate failed: ${response.status} ${response.statusText}`)
  }
}

async function changePassword(id: string, oldPassword: string, newPassword: string): Promise<void> {
  const auth = useAuthStore()
  if (!auth.token) {
    throw new Error('unauthorized')
  }
  const response = await fetch(`/api/users/${id}/change_password`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${auth.token}`,
    },
    body: JSON.stringify({ old_password: oldPassword, password: newPassword }),
  })
  if (!response.ok) {
    throw new Error(`changePassword failed: ${response.status} ${response.statusText}`)
  }
}

async function resetPassword(id: string, password: string): Promise<void> {
  const auth = useAuthStore()
  if (!auth.token) {
    throw new Error('unauthorized')
  }
  const response = await fetch(`/api/users/${id}/reset_password`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${auth.token}`,
    },
    body: JSON.stringify({ password }),
  })
  if (!response.ok) {
    throw new Error(`resetPassword failed: ${response.status} ${response.statusText}`)
  }
}

async function list(offset: number, limit: number): Promise<UserList> {
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

  const response = await fetch('/api/users' + queryString, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${auth.token}`,
    },
  })
  if (!response.ok) {
    throw new Error(`list failed: ${response.status} ${response.statusText}`)
  }
  const { total, users } = await response.json()
  return { total, users }
}

export function useUserStore(): {
  create: (params: CreateRequest) => Promise<void>
  get: (id: string) => Promise<User>
  update: (id: string, params: UpdateRequest) => Promise<void>
  updateStatus: (id: string, status: UserStatus) => Promise<void>
  changePassword: (id: string, oldPwd: string, newPassword: string) => Promise<void>
  resetPassword: (id: string, password: string) => Promise<void>
  list: (offset: number, limit: number) => Promise<UserList>
} {
  return {
    create,
    get,
    update,
    updateStatus,
    changePassword,
    resetPassword,
    list,
  }
}
