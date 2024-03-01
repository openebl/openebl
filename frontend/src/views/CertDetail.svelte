<script lang="ts">
  import { onMount } from 'svelte'
  import { writable } from 'svelte/store'
  import { navigate } from 'svelte-routing'
  import { useAuthStore } from '@stores/auth'
  import { useCertStore, type Certificate } from '@stores/certificate'
  import ConfirmDialog from '@/components/ConfirmDialog.svelte'
  import { truncate } from '@/lib/strutils'

  export let id = ''

  const loading = writable(false)
  const message = writable('')
  const cert = writable(null as Certificate | null)

  const authStore = useAuthStore()
  const certStore = useCertStore()

  const showRevokeConfirmation = writable(false)

  async function fetchCertificate(id: string) {
    try {
      loading.set(true)
      message.set('')
      const data = await certStore.get(id)
      cert.set(data)
    } catch (error) {
      message.set((error as Error).message)
    } finally {
      loading.set(false)
    }
  }

  async function handleRevoke() {
    showRevokeConfirmation.set(true)
  }
  async function handleRevokeConfirm() {
    await certStore.revoke(id)
    await fetchCertificate(id)
  }

  onMount(() => {
    if (!authStore.token) {
      navigate('/login', { replace: true })
    }
    fetchCertificate(id)
  })
</script>

<div class="container">
  <div class="title">Application details</div>
  <div class="header">
    <div>
      <button on:click={() => navigate('/certificates')}>Back</button>
    </div>
    <div>
      {#if $cert?.status !== 'revoked'}
        <button on:click={handleRevoke}>Revoke</button>
      {/if}
    </div>
  </div>

  <div class="details">
    <p>ID: {id}</p>
    <p>Version: {$cert?.version || ''}</p>
    <p>Status: {$cert?.status || ''}</p>
    <p>Type: {$cert?.type || ''}</p>
    <p>CreatedAt: {$cert?.created_at || ''}</p>
    <p>CreatedBy: {$cert?.created_by || ''}</p>
    <p>RevokeAt: {$cert?.revoked_at || ''}</p>
    <p>RevokeBy: {$cert?.revoked_by || ''}</p>
    <p>Private Key: {$cert?.private_key || '[Private Key]'}</p>
    <p>Certificate: {truncate($cert?.certificate || '', 64)}</p>
    <p>Fingerprint: {$cert?.certificate_fingerprint || ''}</p>
  </div>

  <div class="footer"></div>
</div>

<ConfirmDialog
  bind:visible={$showRevokeConfirmation}
  title="Revoke Certificate"
  message="Are you sure you want to revoke this certificate?"
  on:confirm={handleRevokeConfirm} />

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
