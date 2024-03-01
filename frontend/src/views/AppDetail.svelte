<script lang="ts">
  import { onMount } from 'svelte'
  import { writable } from 'svelte/store'
  import { navigate } from 'svelte-routing'
  import { useAuthStore } from '@stores/auth'
  import { useAppStore, type Application, type APIKey } from '@stores/application'
  import ConfirmDialog from '@/components/ConfirmDialog.svelte'
  import AppEdit from './AppEdit.svelte'
  import ApiKeyList from './ApiKeyList.svelte'

  export let id = ''

  const loading = writable(false)
  const message = writable('')
  const app = writable(null as Application | null)

  const authStore = useAuthStore()
  const appStore = useAppStore()

  const showEditForm = writable(false)
  const showConfirmActivate = writable(false)
  const showConfirmDeactivate = writable(false)

  async function fetchApplication(id: string) {
    try {
      loading.set(true)
      message.set('')
      const data = await appStore.get(id)
      app.set(data)
    } catch (error) {
      message.set((error as Error).message)
    } finally {
      loading.set(false)
    }
  }

  async function handleEdit() {
    showEditForm.set(true)
  }
  async function handleActivate() {
    showConfirmActivate.set(true)
  }
  async function handleDeactivate() {
    showConfirmDeactivate.set(true)
  }
  async function handleActivateConfirm() {
    await appStore.updateStatus(id, 'active')
    await fetchApplication(id)
  }
  async function handleDeactivateConfirm() {
    await appStore.updateStatus(id, 'inactive')
    await fetchApplication(id)
  }

  onMount(() => {
    if (!authStore.token) {
      navigate('/login', { replace: true })
    }
    fetchApplication(id)
  })
</script>

<div class="container">
  <div class="title">Application details</div>
  <div class="header">
    <div>
      <button on:click={() => navigate('/applications')}>Back</button>
    </div>
    <div>
      {#if $app}
        <button on:click={handleEdit}>Edit</button>
        {#if $app.status === 'active'}
          <button on:click={handleDeactivate}>Deactivate</button>
        {:else}
          <button on:click={handleActivate}>Activate</button>
        {/if}
      {/if}
    </div>
  </div>

  <div class="details">
    <p>ID: {id}</p>
    <p>Version: {$app?.version || ''}</p>
    <p>Status: {$app?.status || ''}</p>
    <p>CreatedAt: {$app?.created_at || ''}</p>
    <p>CreatedBy: {$app?.created_by || ''}</p>
    <p>UpdatedAt: {$app?.updated_at || ''}</p>
    <p>UpdatedBy: {$app?.updated_by || ''}</p>
    <p>Name: {$app?.name || ''}</p>
    <p>Company Name: {$app?.company_name || ''}</p>
    <p>Address: {$app?.addresses?.join(', ') || ''}</p>
    <p>Email: {$app?.emails?.join(', ') || ''}</p>
    <p>Phone Number: {$app?.phone_numbers?.join(', ') || ''}</p>
  </div>

  <div class="details">
    <ApiKeyList {id} />
  </div>

  <div class="footer"></div>
</div>

<AppEdit {id} bind:showModal={$showEditForm} on:confirm={() => fetchApplication(id)} />

<ConfirmDialog
  bind:visible={$showConfirmActivate}
  title="Activate Application"
  message="Are you sure you want to activate this application?"
  on:confirm={handleActivateConfirm} />

<ConfirmDialog
  bind:visible={$showConfirmDeactivate}
  title="Deactivate Application"
  message="Are you sure you want to deactivate this application?"
  on:confirm={handleDeactivateConfirm} />

<style>
  .container {
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    align-items: center;
  }
  .header {
    min-width: 800px;
    padding: 0 10px;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  .title {
    font-size: 1.5rem;
    font-weight: bold;
  }
  .details {
    min-width: 800px;
    padding: 0 10px;
    text-align: left;
  }
</style>
