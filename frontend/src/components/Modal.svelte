<script>
  import { createEventDispatcher } from 'svelte'

  export let showModal = false
  export let title = 'Confirmation'
  export let confirmText = 'OK'
  export let cancelText = 'Cancel'

  const dispatch = createEventDispatcher()

  const handleConfirm = () => {
    showModal = false
    dispatch('confirm')
  }

  const handleCancel = () => {
    showModal = false
    dispatch('cancel')
  }
</script>

{#if showModal}
  <div class="modal">
    <div class="modal-content">
      {#if title}<p class="title">{title}</p>{/if}
      <slot />
      <div class="buttons">
        <button class="confirm" on:click={handleConfirm}>{confirmText}</button>
        <button class="cancel" on:click={handleCancel}>{cancelText}</button>
      </div>
    </div>
  </div>
{/if}

<style>
  .modal {
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background-color: rgba(0, 0, 0, 0.5); /* Semi-transparent overlay */
    display: flex;
    justify-content: center;
    align-items: center;
    z-index: 999; /* Ensure it appears above other content */
  }

  .modal-content {
    background-color: #000;
    padding: 20px;
    border-radius: 8px;
    box-shadow: 0 0 10px rgba(255, 255, 255, 0.2);
  }

  .title {
    font-weight: bold;
    font-size: 24px;
    margin-top: 0px;
    margin-bottom: 10px;
  }

  .buttons {
    margin-top: 10px;
    text-align: right;
  }

  button {
    padding: 8px 16px;
    margin: 0 8px;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    background-color: #007bff;
    color: #fff;
    font-size: 16px;
  }
  button:hover {
    top: 0.1em;
    background-color: #0056b3;
  }
  button.confirm {
    background-color: #007bff;
  }
  button.confirm:hover {
    background-color: #0056b3;
  }
  button.cancel {
    background-color: #6c757d;
  }
  button.cancel:hover {
    background-color: #5a6268;
  }
</style>
