<script lang="ts">
  import { createEventDispatcher, onMount } from 'svelte'
  import { useAppStore } from '@/stores/application'
  import { writable } from 'svelte/store'

  export let id = ''
  export let showModal = false
  const apiKey = writable('')
  const copyMessage = writable('')
  const errorMessage = writable('')

  const dispatch = createEventDispatcher()

  const handleGenerate = async () => {
    try {
      errorMessage.set('')
      const result = await useAppStore().createApiKey(id)
      apiKey.set(result)
    } catch (err) {
      errorMessage.set(`An error occurred during generate api key. Please try again later. (${(err as Error).message})`)
    }
  }

  const handleCopy = async () => {
    try {
      navigator.clipboard.writeText($apiKey)
      copyMessage.set('successfully copied!')
    } catch (err) {
      errorMessage.set(`An error occurred during copy api key. Please try again later. (${(err as Error).message})`)
    }
  }

  const handleClose = () => {
    showModal = false
    if ($apiKey) {
      dispatch('confirm')
    } else {
      dispatch('cancel')
    }
  }

  onMount(() => {
    apiKey.set('')
    copyMessage.set('')
    errorMessage.set('')
  })
</script>

{#if showModal}
  <div class="modal">
    <div class="modal-content">
      <form class="form-container">
        <div class="form-header">
          <h3>Create New API Key</h3>
        </div>
        <div class="form-field">
          {#if $apiKey}
            <label for="api-key">API Key:</label>
            <textarea id="api-key" name="api-key" bind:value={$apiKey} readonly />
            <button type="button" on:click={handleCopy}>Copy</button>
            <div>
              {#if $copyMessage}{$copyMessage}{/if}
            </div>
          {:else}
            <button type="button" on:click={handleGenerate}>Generate</button>
          {/if}
        </div>
        {#if $errorMessage}
          <p class="error">{$errorMessage}</p>
        {/if}
        <div class="form-field">
          <div class="buttons">
            <button class="confirm" on:click|preventDefault={handleClose}>Close</button>
          </div>
        </div>
        <div class="form-footer">
          <strong>&nbsp;</strong>
        </div>
      </form>
    </div>
  </div>
{/if}

<style>
  * {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
  }

  .modal {
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background-color: rgba(168, 168, 168, 0.5); /* Semi-transparent overlay */
    display: flex;
    justify-content: center;
    align-items: center;
    z-index: 999; /* Ensure it appears above other content */
  }

  .modal-content {
    display: flex;
    justify-content: center;
    align-items: center;
  }

  .form-container {
    width: 500px;
    margin: 0 auto;
    padding: 2rem;
    border-radius: 8px;
    border: 1px solid #ddd;
    box-shadow:
      0 0 10px rgba(255, 255, 255, 0.2),
      0 10px 20px rgba(255, 255, 255, 0.05),
      0 20px 40px rgba(255, 255, 255, 0.05),
      0 40px 80px rgba(255, 255, 255, 0.05);
    background-color: #000;
  }
  .form-field {
    margin-bottom: 0.5rem;
    text-align: left;
    font-family: inherit;
    font-size: 16px;
    font-weight: 700;
    &:last-child {
      margin-bottom: 0;
    }
  }
  .form-field label {
    margin-bottom: 5px;
    color: beige;
    cursor: pointer;
  }
  .form-field button {
    width: 100%;
  }
  .form-field textarea {
    background: #1a1a1a;
    border: 1px solid #ccc;
    width: 100%;
    height: 100px;
    padding: 10px 12px;
    resize: none;
  }
  .buttons {
    display: flex;
    justify-content: center;
    align-items: center;
  }
  .buttons button {
    color: #fff;
    background-color: #007bff;
    border: 1px solid #ddd;
    padding: 10px;
    margin: 0 20px;
    width: 100%;
    text-transform: uppercase;
    cursor: pointer;
    &:hover {
      background-color: #0056b3;
    }
    &:focus {
      outline: none;
    }
  }

  button.confirm {
    background-color: #007bff;
    &:hover {
      background-color: #0056b3;
    }
  }
  .form-header {
    text-align: center;
    margin-bottom: 1rem;
  }
  .form-footer {
    text-align: center;
    margin-top: 1rem;
  }

  .error {
    color: red;
    font-size: 0.8rem;
    margin-top: 0.2rem;
    margin-bottom: 0.2rem;
  }
</style>
