<script lang="ts">
  import { Router, Link, Route } from 'svelte-routing'
  import Home from '@views/Home.svelte'
  import Login from '@views/Login.svelte'
  import Logout from '@views/Logout.svelte'
  import Users from '@/views/UserList.svelte'
  import UserDetail from '@/views/UserDetail.svelte'
  import Applications from '@/views/AppList.svelte'
  import AppDetail from './views/AppDetail.svelte'
  import Certificates from '@/views/CertList.svelte'
  import CertDetail from './views/CertDetail.svelte'
  import NotFound from '@views/NotFound.svelte'
  import { currentUser } from './stores/auth'

  export let url = ''
  let isLoggedIn = false
  currentUser.subscribe((user) => {
    isLoggedIn = !!user
  })
</script>

<main>
  <Router {url}>
    <div class="navbar">
      <div class="nav-left-links">
        <Link to="/">Home</Link>
        <Link to="/users">Users</Link>
        <Link to="/applications">Applications</Link>
        <Link to="/certificates">Certificates</Link>
      </div>
      <div class="nav-right-links">
        {#if isLoggedIn}
          <Link to="/logout">Logout</Link>
        {:else}
          <Link to="/login">Login</Link>
        {/if}
      </div>
    </div>

    <div class="view">
      <Route path="/"><Home /></Route>
      <Route path="/users" component={Users} />
      <Route path="/users/:id" component={UserDetail} />
      <Route path="/applications" component={Applications} />
      <Route path="/applications/:id" component={AppDetail} />
      <Route path="/certificates" component={Certificates} />
      <Route path="/certificates/:id" component={CertDetail} />
      <Route path="/login" component={Login} />
      <Route path="/logout" component={Logout} />
      <Route path="*" component={NotFound} />
    </div>
  </Router>
</main>

<style>
  main {
    display: flex;
    flex-direction: column;
    align-items: center;
    width: 100%;
  }

  .navbar {
    display: flex;
    gap: 10px;
    margin-bottom: 20px;
    width: 100%;
    overflow: auto;
    height: auto;
    justify-content: space-between;
  }

  .nav-left-links {
    display: flex;
    gap: 10px;
    justify-content: flex-start;
    margin-right: auto;
  }

  .nav-right-links {
    display: flex;
    gap: 10px;
    margin-left: auto;
    justify-content: flex-end;
  }

  .view {
    width: 100%;
  }
</style>
