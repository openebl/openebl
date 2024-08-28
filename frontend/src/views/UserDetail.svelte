<script lang="ts">
  import { onMount } from 'svelte'
  import { derived, writable } from 'svelte/store'
  import { navigate } from 'svelte-routing'
  import { useAuthStore } from '@stores/auth'
  import { useUserStore, type User } from '@stores/user'
  import ConfirmDialog from '@/components/ConfirmDialog.svelte'
  import UserEdit from './UserEdit.svelte'
  import UserChangePassword from './UserChangePassword.svelte'
  import UserResetPassword from './UserResetPassword.svelte'

  export let id = ''

  const loading = writable(false)
  const message = writable('')
  const user = writable(null as User | null)

  const authStore = useAuthStore()
  const userStore = useUserStore()

  const showEditForm = writable(false)
  const showChangePasswordForm = writable(false)
  const showResetPasswordForm = writable(false)
  const showConfirmActivate = writable(false)
  const showConfirmDeactivate = writable(false)

  async function fetchUser(id: string) {
    try {
      loading.set(true)
      message.set('')
      const data = await userStore.get(id)
      user.set(data)
    } catch (error) {
      message.set((error as Error).message)
    } finally {
      loading.set(false)
    }
  }

  async function handleEdit() {
    showEditForm.set(true)
  }
  async function handleResetPassword() {
    showResetPasswordForm.set(true)
  }
  async function handleChangePassword() {
    showChangePasswordForm.set(true)
  }
  async function handleActivate() {
    showConfirmActivate.set(true)
  }
  async function handleDeactivate() {
    showConfirmDeactivate.set(true)
  }
  async function handleActivateConfirm() {
    await userStore.updateStatus(id, 'active')
    await fetchUser(id)
  }
  async function handleDeactivateConfirm() {
    await userStore.updateStatus(id, 'inactive')
    await fetchUser(id)
  }

  onMount(() => {
    if (!authStore.token) {
      navigate('/login', { replace: true })
    }
    fetchUser(id)
  })
</script>

<div class="container">
  <div class="title">User details</div>
  <div class="header">
    <div>
      <button on:click={() => navigate('/users')}>Back</button>
    </div>
    <div>
      {#if $user}
        <button on:click={handleEdit}>Edit</button>
        {#if $user.id === authStore.userId}
          <button on:click={handleChangePassword}>Change Password</button>
        {:else}
          <button on:click={handleResetPassword}>Reset Password</button>
          {#if $user.status === 'active'}
            <button on:click={handleDeactivate}>Deactivate</button>
          {:else}
            <button on:click={handleActivate}>Activate</button>
          {/if}
        {/if}
      {/if}
    </div>
  </div>

  <div class="details">
    <p>ID: {id}</p>
    <p>Username: {$user?.username || ''}</p>
    <p>Status: {$user?.status || ''}</p>
    <p>Version: {$user?.version || ''}</p>
    <p>Name: {$user?.name || ''}</p>
    <p>Emails: {$user?.emails?.join(',') || ''}</p>
    <p>Note: {$user?.note || ''}</p>
    <p>CreatedAt: {$user?.created_at || ''}</p>
    <p>CreatedBy: {$user?.created_by || ''}</p>
    <p>UpdatedAt: {$user?.updated_at || ''}</p>
    <p>UpdatedBy: {$user?.updated_by || ''}</p>
  </div>

  <div class="footer"></div>
</div>

<UserEdit
  {id}
  bind:showModal={$showEditForm}
  on:confirm={() => {
    fetchUser(id)
  }} />

<UserChangePassword
  {id}
  username={$user?.username}
  bind:showModal={$showChangePasswordForm}
  on:confirm={() => {
    fetchUser(id)
  }} />

<UserResetPassword
  {id}
  username={$user?.username}
  bind:showModal={$showResetPasswordForm}
  on:confirm={() => {
    fetchUser(id)
  }} />

<ConfirmDialog
  bind:visible={$showConfirmActivate}
  title="Activate User"
  message="Are you sure you want to activate this user?"
  on:confirm={handleActivateConfirm} />

<ConfirmDialog
  bind:visible={$showConfirmDeactivate}
  title="Deactivate User"
  message="Are you sure you want to deactivate this user?"
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
