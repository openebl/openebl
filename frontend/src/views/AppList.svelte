<script lang="ts">
  import { onMount } from 'svelte'
  import { useAuthStore } from '@stores/auth'
  import { useAppStore, type Application } from '@stores/application'
  import { navigate } from 'svelte-routing'
  import { writable } from 'svelte/store'
  import AppForm from './AppForm.svelte'
  import Paginator from '@/components/Paginator.svelte'

  const authStore = useAuthStore()
  const appStore = useAppStore()

  let loading = writable(false)
  let message = writable('')
  const apps = writable([] as Application[])
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
      const response = await appStore.list(offset, limit)
      paginationSettings.size = response.total || 0
      apps.set(response.apps || [])
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

<h3>Applications</h3>
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
      <th>ID</th>
      <th>Name</th>
      <th>Status</th>
      <th>Company Name</th>
      <th>&nbsp;</th>
    </tr>
  </thead>
  <tbody>
    {#each $apps as app}
      <tr>
        <td>{app.id}</td>
        <td>{app.name}</td>
        <td>{app.status}</td>
        <td>{app.company_name}</td>
        <td>
          <button on:click|preventDefault={() => navigate(`/applications/${app.id}`)}>Detail</button>
        </td>
      </tr>
    {:else}
      <tr>
        <td colSpan="5">No applications found</td>
      </tr>
    {/each}
  </tbody>
</table>

<Paginator bind:settings={paginationSettings} on:page={onPageChange} />

<AppForm bind:showModal={$showNewForm} on:confirm={fetchData} />

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
