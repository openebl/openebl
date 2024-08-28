<script lang="ts">
  import { onMount } from 'svelte'
  import { useAuthStore } from '@stores/auth'
  import { navigate } from 'svelte-routing'
  import * as yup from 'yup'

  const schema = yup.object().shape({
    username: yup.string().required('username is required'),
    password: yup.string().required('Password is required'),
  })

  let username = ''
  let password = ''
  let errors = {} as any
  let loginError = ''

  // Access the auth store
  const authStore = useAuthStore()
  onMount(() => {
    // Check if the user is already logged in
    if (!!authStore.token) {
      // If the user is already logged in, navigate to the home page
      navigate('/', { replace: true })
    }
  })

  // Function to handle login submission
  const handleLogin = async () => {
    try {
      // Validate the form fields
      await schema.validate({ username, password }, { abortEarly: false })
      errors = {}

      // Call the login method on the auth store
      await authStore.login(username, password)
      navigate('/', { replace: true })
    } catch (error) {
      if (error instanceof yup.ValidationError) {
        // Set the errors to be displayed
        errors = error.inner.reduce((acc: any, { path, message }) => {
          return {
            ...acc,
            [path as string]: message,
          }
        }, {})
      } else {
        // Set the error message to be displayed
        loginError = `An error occurred during login. Please try again later. (${(error as Error).message})`
      }
    }
  }
</script>

<div class="wrap">
  <form class="form-container" on:submit|preventDefault={handleLogin}>
    <div class="form-header">
      <h2>Login</h2>
      {#if loginError}
        <span style="color: red;">{loginError}</span>
      {/if}
    </div>
    <div class="form-field">
      <label for="username">Username:</label>
      <input type="text" id="username" bind:value={username} />
      {#if errors.username}<span class="error">{errors.username}</span>{/if}
    </div>
    <div class="form-field">
      <label for="password">Password:</label>
      <input type="password" id="password" bind:value={password} />
      {#if errors.password}<span class="error">{errors.password}</span>{/if}
    </div>
    <div class="form-field">
      <button type="submit">Login</button>
    </div>
    <div class="form-footer"></div>
  </form>
</div>

<style>
  * {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
  }
  .wrap {
    width: 100%;
    height: 100%;
    display: flex;
    justify-content: center;
    align-items: center;
  }
  .form-container {
    width: 450px;
    margin: 0 auto;
    padding: 1rem 2rem;
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
    margin-bottom: 1rem;
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
    color: #fff;
    background-color: #007bff;
    border: 1px solid #ddd;
    padding: 10px;
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
  }
</style>
