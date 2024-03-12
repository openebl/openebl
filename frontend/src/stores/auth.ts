import { get, writable, type Writable } from 'svelte/store'

interface AuthStore {
  user_id: string
  token: string
}

let token = ''
let userId = ''
const persistedUser = sessionStorage.getItem('user')
export const currentUser: Writable<AuthStore | null> = writable<AuthStore>(
  persistedUser ? JSON.parse(persistedUser) : null,
)
currentUser.subscribe((value) => {
  token = value?.token || ''
  userId = value?.user_id || ''
  sessionStorage.setItem('user', JSON.stringify(value))
})

async function login(username: string, password: string): Promise<void> {
  if (!username || !password) throw new Error('username and password are required')

  const response = await fetch('/api/login', {
    method: 'GET',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Basic ${btoa(`${username}:${password}`)}`,
    },
  })
  if (!response.ok) {
    throw new Error(`login failed: ${response.status} ${response.statusText}`)
  }
  const data = await response.json()
  currentUser.set(data)
}
async function logout(): Promise<void> {
  currentUser.set(null)
}

export function useAuthStore(): {
  userId: string
  token: string
  login: (username: string, password: string) => Promise<void>
  logout: () => Promise<void>
} {
  return {
    userId,
    token,
    login,
    logout,
  }
}
