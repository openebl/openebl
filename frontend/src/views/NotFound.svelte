<script lang="ts">
  import { navigate } from 'svelte-routing'

  // Function to navigate back to the home page
  const goToHome = () => {
    navigate('/')
  }
</script>

<div class="container">
  <h1>404 Not Found</h1>
  <p>Oops! The page you are looking for does not exist.</p>
  <button on:click={goToHome}>Go to Home</button>
</div>

<style>
  .container {
    text-align: center;
    margin-top: 50px;
  }
</style>
