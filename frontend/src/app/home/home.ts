import { Component, computed, inject, signal } from '@angular/core';
import { ConnectionDto, ConnectionStatus, ConnectionsResponse, ProviderKey, WorkspaceApi } from '../workspace-api.service';

const PROVIDER_ORDER: ProviderKey[] = ['google', 'github', 'discord'];

@Component({
  selector: 'app-home',
  templateUrl: './home.html',
  styleUrl: './home.css',
})
export class Home {
  private readonly api = inject(WorkspaceApi);
  readonly providerOrder = PROVIDER_ORDER;
  readonly loading = signal(true);
  readonly loadError = signal(false);
  readonly snapshot = signal<ConnectionsResponse | null>(null);
  readonly busy = signal<ProviderKey | null>(null);
  readonly notice = signal<{ message: string; error: boolean } | null>(null);
  readonly demoMode = computed(() => this.snapshot()?.demoMode ?? false);
  readonly connectionSummary = computed(() => {
    const connections = this.snapshot()?.connections ?? [];
    return {
      connected: connections.filter((item) => item.status === 'connected').length,
      attention: connections.filter((item) => item.status === 'reauth_required').length,
      refreshable: connections.filter((item) => item.canRefreshAccessToken).length,
    };
  });

  constructor() {
    this.consumeOAuthResult();
    this.loadWorkspace();
  }

  loadWorkspace(): void {
    this.loading.set(true);
    this.loadError.set(false);
    this.api.loadWorkspace().subscribe({
      next: (response) => {
        this.snapshot.set(response);
        this.busy.set(null);
        this.loading.set(false);
        if (response.session?.workspaceRecoveryRequired) {
          this.notice.set({
            message: 'Could not restore saved connection data. Reconnect your accounts.',
            error: true,
          });
        }
      },
      error: () => {
        this.busy.set(null);
        this.loadError.set(true);
        this.loading.set(false);
      },
    });
  }

  connectionFor(provider: ProviderKey): ConnectionDto | null {
    return this.snapshot()?.connections.find((item) => item.provider === provider) ?? null;
  }

  startConnection(provider: ProviderKey): void {
    this.api.startProvider(provider);
  }

  connectLabel(connection: ConnectionDto): string {
    return connection.status === 'reauth_required'
      ? `Reconnect ${connection.label}`
      : `Connect ${connection.label}`;
  }

  statusLabel(status: ConnectionStatus): string {
    switch (status) {
      case 'connected': return 'Connected';
      case 'reauth_required': return 'Needs authorization';
      case 'not_configured': return 'Not configured';
      default: return 'Not connected';
    }
  }

  setupMessage(connection: ConnectionDto): string | null {
    if (connection.configured && this.demoMode())
      return 'Live sign-in is disabled in demo mode.';
    if (!connection.configured)
      return 'Add this provider’s OAuth credentials on the server.';
    return null;
  }

  oauthContractFor(provider: ProviderKey) {
    return this.snapshot()?.oauthProviders?.find((item) => item.provider === provider) ?? null;
  }

  pkceLabel(provider: ProviderKey): string {
    return this.oauthContractFor(provider)?.pkceMethod ?? 'Not used in this provider flow';
  }

  grantedScopesLabel(connection: ConnectionDto): string {
    if (connection.grantedScopes && connection.grantedScopes.length > 0)
      return connection.grantedScopes.join(' · ');
    if (connection.grantedScopes)
      return 'No scopes reported';
    return connection.status === 'connected'
      || connection.status === 'reauth_required'
      ? 'Not reported by provider'
      : 'No grant';
  }

  accessTokenExpiryLabel(connection: ConnectionDto): string {
    if (!connection.accessTokenExpiresAt)
      return connection.status === 'connected'
        || connection.status === 'reauth_required'
        ? 'Not provided by provider'
        : 'No token';
    const expiry = new Date(connection.accessTokenExpiresAt);
    if (Number.isNaN(expiry.getTime()))
      return 'Unknown';
    const minutes = Math.ceil((expiry.getTime() - Date.now()) / 60_000);
    if (minutes <= 0)
      return 'Expired';
    if (minutes < 60)
      return `In ${minutes} min`;
    return expiry.toLocaleString();
  }

  refreshTokenLabel(connection: ConnectionDto): string {
    if (connection.status === 'not_connected' || connection.status === 'not_configured')
      return 'No grant';
    return connection.canRefreshAccessToken
      ? 'Available; stored on server'
      : 'Not available';
  }

  async copyCallback(provider: ProviderKey): Promise<void> {
    const callbackUri = this.oauthContractFor(provider)?.callbackUri;
    if (!callbackUri) {
      this.notice.set({ message: 'Callback URL is unavailable.', error: true });
      return;
    }
    try {
      await navigator.clipboard.writeText(callbackUri);
      this.notice.set({ message: 'Callback URL copied.', error: false });
    } catch {
      this.notice.set({ message: 'Copy the callback URL from the details above.', error: true });
    }
  }

  profileName(connection: ConnectionDto): string | null {
    return connection.profile?.displayName || connection.profile?.identifier || null;
  }

  profileIdentifier(connection: ConnectionDto): string | null {
    const profile = connection.profile;
    if (!profile) return null;
    return profile.identifier
      && profile.identifier !== profile.displayName
      && profile.identifier !== profile.email
      ? profile.identifier
      : null;
  }

  profileEmail(connection: ConnectionDto): string | null {
    return connection.profile?.email ?? null;
  }

  verifyGrant(provider: ProviderKey): void {
    const connection = this.connectionFor(provider);
    if (!connection || connection.status !== 'connected' || this.busy()) return;
    this.busy.set(provider);
    this.api.refreshConnection(provider).subscribe({
      next: (response) => {
        this.snapshot.set(this.withCurrentSession(response));
        this.busy.set(null);
        const refreshed = response.connections.find((item) => item.provider === provider);
        this.notice.set({
          message: refreshed?.status === 'connected'
            ? `${refreshed.label} grant verified.`
            : `${refreshed?.label ?? 'Provider'} needs attention.`,
          error: refreshed?.status !== 'connected',
        });
      },
      error: () => {
        this.busy.set(null);
        this.notice.set({ message: 'Could not verify this connection. Try again.', error: true });
      },
    });
  }

  disconnect(connection: ConnectionDto): void {
    if (this.busy() || connection.status === 'not_connected' || connection.status === 'not_configured')
      return;
    if (!window.confirm(`Remove the ${connection.label} connection from this browser?`)) return;
    this.busy.set(connection.provider);
    this.api.disconnect(connection.provider).subscribe({
      next: () => this.loadWorkspace(),
      error: () => {
        this.busy.set(null);
        this.notice.set({ message: `${connection.label} could not be removed. Try again.`, error: true });
      },
    });
  }

  timeAgo(value: string | null): string {
    if (!value) return 'Not checked yet';
    const elapsedSeconds = Math.max(0, (Date.now() - new Date(value).getTime()) / 1000);
    const units: Array<[Intl.RelativeTimeFormatUnit, number]> = [
      ['year', 31_536_000], ['month', 2_592_000], ['day', 86_400], ['hour', 3_600], ['minute', 60],
    ];
    const selected = units.find(([, threshold]) => elapsedSeconds >= threshold) ?? ['second', 1];
    return new Intl.RelativeTimeFormat('en', { numeric: 'auto' })
      .format(-Math.floor(elapsedSeconds / selected[1]), selected[0]);
  }

  private consumeOAuthResult(): void {
    const params = new URLSearchParams(window.location.search);
    const result = params.get('oauth');
    const provider = params.get('provider');
    const reason = params.get('reason');
    if (result) {
      const label = this.providerLabel(provider);
      const message = result === 'connected'
        ? `${label} connected.`
        : this.oauthErrorMessage(label, reason);
      this.notice.set({ message, error: result === 'error' });
      window.history.replaceState({}, document.title, window.location.pathname + window.location.hash);
    }
  }

  private oauthErrorMessage(provider: string, reason: string | null): string {
    switch (reason) {
      case 'access_denied': return `${provider} access was not approved. No new connection was saved.`;
      case 'not_configured': return `${provider} credentials are missing on the server.`;
      case 'demo_mode': return 'Live sign-in is disabled in demo mode.';
      case 'csrf_validation_failed': return 'This browser session expired. Reload the page and start again.';
      case 'state_mismatch': return 'The OAuth callback could not be verified. Start the connection again.';
      case 'session_expired': return 'This browser workspace expired. Reload the page and start again.';
      default: return `${provider} sign-in failed. Check the provider settings and try again.`;
    }
  }

  private providerLabel(value: string | null): string {
    switch (value) {
      case 'google': return 'Google';
      case 'discord': return 'Discord';
      case 'github': return 'GitHub';
      default: return 'Provider';
    }
  }

  private withCurrentSession(response: ConnectionsResponse): ConnectionsResponse {
    const session = this.snapshot()?.session;
    return response.session || !session ? response : { ...response, session };
  }
}
