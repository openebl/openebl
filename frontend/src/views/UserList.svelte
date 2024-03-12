<script lang="ts">
  import { onMount } from 'svelte'
  import { useAuthStore } from '@stores/auth'
  import { useUserStore, type User } from '@stores/user'
  import { navigate } from 'svelte-routing'
  import { writable } from 'svelte/store'
  import UserForm from './UserForm.svelte'
  import Paginator from '@/components/Paginator.svelte'

  const authStore = useAuthStore()
  const userStore = useUserStore()

  let loading = writable(false)
  let message = writable('')
  const users = writable([] as User[])
  let paginationSettings = {
    page: 0,
    limit: 10,
    size: 0,
    amounts: [],
  }

  async function fetchData() {
    try {
      loading.set(true)
      const offset = paginationSettings.page * paginationSettings.limit
      const limit = paginationSettings.limit
      const response = await userStore.list(offset, limit)
      paginationSettings.size = response.total || 0
      users.set(response.users || [])
      message.set('')
    } catch (error) {
      message.set((error as Error).message)
    } finally {
      loading.set(false)
    }
  }
  const onPageChange = async (e: CustomEvent) => {
    const page = e.detail
    paginationSettings.page = page
    await fetchData()
  }

  const showNewForm = writable(false)
  async function handleNew() {
    showNewForm.set(true)
  }

  onMount(() => {
    if (!authStore.token) {
      navigate('/login', { replace: true })
    }
    fetchData()
  })
</script>

<h3>Users</h3>
<div style="display:flex; justify-content:right;">
  <button on:click|preventDefault={handleNew}>New</button>
</div>

{#if $loading}
  <span>Loading...</span>
{/if}
{#if $message}
  <span style="color: red;">{$message}</span>
{/if}

<table>
  <thead>
    <tr>
      <th>Username</th>
      <th>Name</th>
      <th>Status</th>
      <th>Note</th>
      <th>&nbsp;</th>
    </tr>
  </thead>
  <tbody>
    {#each $users as user}
      <tr>
        <td>{user.username}</td>
        <td>{user.name}</td>
        <td>{user.status}</td>
        <td>{user.note}</td>
        <td>
          <button on:click|preventDefault={() => navigate(`/users/${user.id}`)}>Detail</button>
        </td>
      </tr>
    {:else}
      <tr>
        <td colSpan="5">No users found</td>
      </tr>
    {/each}
  </tbody>
</table>

<Paginator bind:settings={paginationSettings} on:page={onPageChange} />

<UserForm bind:showModal={$showNewForm} on:confirm={fetchData} />

<style>
  table {
    width: 100%;
    border-collapse: collapse;
  }
  th,
  td {
    padding: 0.5rem;
    border: 1px solid #ddd;
    text-align: left;
  }
  th {
    background-color: #2f2f2f;
  }
  tr:nth-child(even) {
    background-color: #3d3d3d;
  }
</style>
