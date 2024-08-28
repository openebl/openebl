<script lang="ts">
  import { useAuthStore } from '@stores/auth'
  import { navigate } from 'svelte-routing'
  import { onMount } from 'svelte'

  const authStore = useAuthStore()

  onMount(() => {
    if (!authStore.token) {
      navigate('/login', { replace: true })
    }
  })

  // Function to handle logout
  const handleLogout = async () => {
    await authStore.logout()
    navigate('/login', { replace: true })
  }
</script>

<div>
  <h3>Logout?</h3>
  <button on:click={handleLogout}>Yes</button>
</div>
