<script lang="ts">
  import * as yup from 'yup'
  import { createEventDispatcher, onMount } from 'svelte'
  import { useCertStore, type CreateRequest } from '@/stores/certificate'

  export let showModal = false
  let cert: CreateRequest = {
    cert: '',
    private_key: '',
  }
  let errorMessage = ''
  let errors: { [key: string]: string } = {}

  const dispatch = createEventDispatcher()

  const schema = yup.object({
    cert: yup.string().required('certificate is required'),
    private_key: yup.string().required('private key is required'),
  })

  const handleSubmit = async () => {
    try {
      await schema.validate(cert, { abortEarly: false })
      await useCertStore().create(cert)
      showModal = false
      dispatch('confirm')
    } catch (err) {
      if (err instanceof yup.ValidationError) {
        errors = {}
        console.log(err.inner)
        err.inner.forEach((e) => {
          errors[e.path as string] = e.message
        })
      } else {
        errorMessage = `An error occurred during certificate creation. Please try again later. (${(err as Error).message})`
      }
    }
  }
  const handleCertFile = async (event: Event) => {
    const target = event.target as HTMLInputElement
    const file = target.files as FileList
    if (file?.[0]) {
      const reader = new FileReader()
      reader.onload = () => {
        cert.cert = reader.result as string
      }
      reader.readAsText(file[0])
    }
  }
  const handleKeyFile = async (event: Event) => {
    const target = event.target as HTMLInputElement
    const file = target.files as FileList
    if (file?.[0]) {
      const reader = new FileReader()
      reader.onload = () => {
        cert.private_key = reader.result as string
      }
      reader.readAsText(file[0])
    }
  }

  const handleCancel = () => {
    showModal = false
    dispatch('cancel')
  }

  onMount(() => {
    cert = {
      cert: '',
      private_key: '',
    }
    errorMessage = ''
    errors = {}
  })
</script>

{#if showModal}
  <div class="modal">
    <div class="modal-content">
      <form class="form-container">
        <div class="form-header">
          <h3>Create New Certificate</h3>
        </div>
        <div class="form-field">
          <label for="name">Certificate:</label>
          <input id="certFile" name="certFile" type="file" on:change={handleCertFile} />
          <textarea id="cert" name="cert" bind:value={cert.cert}></textarea>
          {#if errors.cert}<p class="error">{errors.cert}</p>{/if}
        </div>
        <div class="form-field">
          <label for="name">Private Key:</label>
          <input id="keyFile" name="keyFile" type="file" on:change={handleKeyFile} />
          <textarea id="private_key" name="private_key" bind:value={cert.private_key}></textarea>
          {#if errors.private_key}<p class="error">{errors.private_key}</p>{/if}
        </div>
        {#if errorMessage}
          <p class="error">{errorMessage}</p>
        {/if}
        <div class="form-field">
          <div class="buttons">
            <button class="confirm" on:click|preventDefault={handleSubmit}>Submit</button>
            <button class="cancel" on:click|preventDefault={handleCancel}>Cancel</button>
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
  .form-field input {
    background: #1a1a1a;
    border: 1px solid #ccc;
    width: 100%;
    padding: 10px 12px;
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
  button.cancel {
    background-color: #6c757d;
    &:hover {
      background-color: #5a6268;
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
