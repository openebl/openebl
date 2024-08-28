<script lang="ts">
  import { onMount } from 'svelte'
  import { useAuthStore } from '@stores/auth'
  import { useAppStore, type APIKey } from '@stores/application'
  import { navigate } from 'svelte-routing'
  import { writable } from 'svelte/store'
  import ApiKeyForm from './ApiKeyForm.svelte'
  import ConfirmDialog from '@/components/ConfirmDialog.svelte'
  import Paginator from '@/components/Paginator.svelte'

  export let id = ''
  const authStore = useAuthStore()
  const appStore = useAppStore()

  let loading = writable(false)
  let message = writable('')
  const keys = writable([] as APIKey[])
  const revokeApiKeyId = writable('')
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
      const response = await appStore.listApiKeys(id, offset, limit)
      paginationSettings.size = response.total || 0
      keys.set(response.keys || [])
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

  const showRevokeConfirm = writable(false)
  async function handleRevoke(id: string) {
    revokeApiKeyId.set(id)
    showRevokeConfirm.set(true)
  }
  async function handleRevokeConfirm() {
    const keyId = $revokeApiKeyId
    revokeApiKeyId.set('')

    if (!keyId) return

    try {
      await appStore.revokeApiKey(id, keyId)
      message.set('')
    } catch (error) {
      message.set((error as Error).message)
    } finally {
      fetchData()
      showRevokeConfirm.set(false)
    }
  }

  onMount(() => {
    if (!authStore.token) {
      navigate('/login', { replace: true })
    }
    fetchData()
  })
</script>

<h3>API Keys ({id})</h3>
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
      <th>Status</th>
      <th>Scopes</th>
      <th>Created At</th>
      <th>Updated At</th>
      <th><button on:click|preventDefault={handleNew}>New</button></th>
    </tr>
  </thead>
  <tbody>
    {#each $keys as key}
      <tr>
        <td>{key.id}</td>
        <td>{key.status}</td>
        <td>{(key.scopes || []).join(',')}</td>
        <td>{key.created_at}</td>
        <td>{key.updated_at}</td>
        <td>
          {#if key.status === 'active'}<button on:click|preventDefault={() => handleRevoke(key.id)}>Revoke</button>{/if}
        </td>
      </tr>
    {:else}
      <tr>
        <td colSpan="6">No api keys found</td>
      </tr>
    {/each}
  </tbody>
</table>

<Paginator bind:settings={paginationSettings} on:page={onPageChange} />

<ApiKeyForm {id} bind:showModal={$showNewForm} on:confirm={fetchData} />

<ConfirmDialog
  title="Revoke API Key"
  message="Are you sure you want to revoke this API key?"
  confirmText="Revoke"
  cancelText="Cancel"
  bind:visible={$showRevokeConfirm}
  on:confirm={handleRevokeConfirm}
  on:cancel={() => revokeApiKeyId.set('')} />

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
