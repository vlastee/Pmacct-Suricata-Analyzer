// Global auth state. `authDisabled` means the backend runs with AUTH_ENABLED=false.
import { api, ApiError, type AuthUser } from './api'

class Auth {
  user = $state<AuthUser | null>(null)
  loading = $state(true)
  authDisabled = $state(false)
  mustChange = $state(false)

  async refresh() {
    this.loading = true
    try {
      const m = await api.me()
      if (!m.auth) { this.authDisabled = true; this.user = null; this.mustChange = false }
      else { this.user = m.user ?? null; this.mustChange = !!m.must_change_password }
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) { this.user = null; this.mustChange = false }
      // other errors: leave as logged-out
      else { this.user = null }
    } finally {
      this.loading = false
    }
  }

  async login(username: string, password: string) {
    const r = await api.login(username, password)
    this.user = r.user
    this.mustChange = r.must_change_password
    this.authDisabled = false
  }

  async logout() {
    try { await api.logout() } catch {}
    this.user = null
    this.mustChange = false
  }

  get authed() { return this.authDisabled || (this.user !== null && !this.mustChange) }
}

export const auth = new Auth()
