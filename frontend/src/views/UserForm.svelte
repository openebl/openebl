<script lang="ts">
  import * as yup from 'yup'
  import { createEventDispatcher, onMount } from 'svelte'
  import { useUserStore, type CreateRequest } from '@/stores/user'

  export let showModal = false
  let user: CreateRequest = {
    username: '',
    password: '',
    name: '',
    emails: [],
    note: '',
  }
  let errorMessage = ''
  let errors: { [key: string]: string } = {}

  const dispatch = createEventDispatcher()

  const schema = yup.object({
    username: yup.string().required('username is required').min(4).lowercase(),
    password: yup.string().required('password is required').min(8),
    name: yup.string(),
    emails: yup.array().of(yup.string().email()),
    note: yup.string(),
  })

  const addEmail = () => {
    user.emails.push('')
    user = { ...user } // Force reactivity
  }
  const removeEmail = (index: number) => {
    user.emails.splice(index, 1)
    user = { ...user } // Force reactivity
  }

  const handleSubmit = async () => {
    try {
      errors = {}
      errorMessage = ''

      await schema.validate(user, { abortEarly: false })
      await useUserStore().create(user)

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
        errorMessage = `An error occurred during creation. Please try again later. (${(err as Error).message})`
      }
    }
  }

  const handleCancel = () => {
    showModal = false
    dispatch('cancel')
  }

  onMount(() => {
    user = {
      username: '',
      password: '',
      name: '',
      emails: [],
      note: '',
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
          <h3>Create New User</h3>
        </div>
        <div class="form-field">
          <label for="username">Username:</label>
          <input id="username" name="username" type="text" bind:value={user.username} />
          {#if errors.username}<p class="error">{errors.username}</p>{/if}
        </div>
        <div class="form-field">
          <label for="password">Password:</label>
          <input id="password" name="password" type="password" bind:value={user.password} />
          {#if errors.password}<p class="error">{errors.password}</p>{/if}
        </div>
        <div class="form-field">
          <label for="name">Name:</label>
          <input id="name" name="name" type="text" bind:value={user.name} />
          {#if errors.name}<p class="error">{errors.name}</p>{/if}
        </div>
        <div class="form-field">
          <label for="note">Note:</label>
          <input id="note" name="note" type="text" bind:value={user.note} />
          {#if errors.note}<p class="error">{errors.note}</p>{/if}
        </div>
        <div class="form-field">
          <label for="emails">Emails:</label>
          {#each user.emails as email, index}
            {@const emailError = errors[`emails[${index}]`]}
            <div>
              <div class="email-input">
                <input type="text" bind:value={user.emails[index]} />
                <button type="button" on:click={() => removeEmail(index)}>Remove</button>
              </div>
              {#if emailError}<p class="error">{emailError}</p>{/if}
            </div>
          {/each}
          <button type="button" on:click={addEmail}>Add Email</button>
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
  .form-field input[type='text'],
  [type='password'] {
    box-sizing: border-box;
  }
  .form-field button {
    width: 100%;
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
  .email-input {
    display: flex;
    margin-bottom: 5px;
  }
  .email-input input {
    flex: 1;
    margin-right: 5px;
  }
  .email-input button {
    width: 100px;
  }
  .error {
    color: red;
    font-size: 0.8rem;
    margin-top: 0.2rem;
    margin-bottom: 0.2rem;
  }
</style>
