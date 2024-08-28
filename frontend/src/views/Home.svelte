<script lang="ts">
  import { onMount } from 'svelte'
  import { useAuthStore } from '@stores/auth'
  import { navigate } from 'svelte-routing'

  const authStore = useAuthStore()

  onMount(() => {
    if (!authStore.token) {
      navigate('/login', { replace: true })
    }
  })
</script>

<div>
  <h3>Welcome Back!</h3>
</div>
