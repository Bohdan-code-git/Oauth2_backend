import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Injectable, inject, signal } from '@angular/core';
import { Observable, forkJoin, map, switchMap, tap } from 'rxjs';

export type ProviderKey = 'google' | 'github' | 'discord';
export type ConnectionStatus =
  | 'not_configured'
  | 'not_connected'
  | 'connected'
  | 'reauth_required';

export interface ProviderProfile {
  displayName: string | null;
  identifier: string | null;
  email: string | null;
  avatarUrl: string | null;
  profileUrl: string | null;
}

export interface ConnectionDto {
  provider: ProviderKey;
  label: string;
  status: ConnectionStatus;
  configured: boolean;
  profile: ProviderProfile | null;
  connectedAt: string | null;
  lastSyncedAt: string | null;
  accessTokenExpiresAt: string | null;
  canRefreshAccessToken: boolean;
  grantedScopes: string[] | null;
  message: string | null;
}

export interface ConnectionsResponse {
  demoMode: boolean;
  generatedAt: string;
  connections: ConnectionDto[];
  oauthFeedback?: OAuthFeedback[] | null;
  oauthProviders?: OAuthProviderInfo[];
  session?: SessionResponse;
}

export interface OAuthFeedback {
  provider: ProviderKey;
  reason: string;
}

export interface OAuthProviderInfo {
  provider: ProviderKey;
  label: string;
  configured: boolean;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  callbackUri: string | null;
  responseType: 'code';
  scopes: string[];
  pkceMethod: 'S256' | null;
  profileEndpoints: string[];
  authorizationParameters: Array<{ name: string; value: string }>;
}

interface OAuthProvidersResponse {
  demoMode: boolean;
  providers: OAuthProviderInfo[];
}

export interface SessionResponse {
  application: string;
  accessMode: 'browser_workspace';
  mode: 'demo' | 'live';
  csrfToken: string;
  workspaceRecoveryRequired?: boolean;
}

@Injectable({ providedIn: 'root' })
export class WorkspaceApi {
  private readonly http = inject(HttpClient);
  private readonly csrfToken = signal('');

  loadWorkspace(): Observable<ConnectionsResponse> {
    return this.http
      .get<SessionResponse>('/api/session', { withCredentials: true })
      .pipe(
        tap((session) => this.csrfToken.set(session.csrfToken)),
        switchMap((session) => {
          return forkJoin({
            connections: this.http.get<ConnectionsResponse>('/api/connections', {
              withCredentials: true,
            }),
            providers: this.http.get<OAuthProvidersResponse>('/api/oauth/providers', {
              withCredentials: true,
            }),
          }).pipe(map(({ connections, providers }) => ({
            ...connections,
            oauthProviders: providers.providers,
            session,
          })));
        }),
      );
  }

  refreshConnections(): Observable<ConnectionsResponse> {
    return this.http.post<ConnectionsResponse>(
      '/api/connections/refresh',
      {},
      this.mutationOptions(),
    );
  }

  refreshConnection(provider: ProviderKey): Observable<ConnectionsResponse> {
    return this.http.post<ConnectionsResponse>(
      '/api/connections/' + provider + '/refresh',
      {},
      this.mutationOptions(),
    );
  }

  disconnect(provider: ProviderKey): Observable<void> {
    return this.http.delete<void>(
      '/api/connections/' + provider,
      this.mutationOptions(),
    );
  }

  startProvider(provider: ProviderKey): void {
    const form = document.createElement('form');
    form.method = 'post';
    form.action = `/api/connections/${provider}/start`;
    form.hidden = true;

    const csrf = document.createElement('input');
    csrf.type = 'hidden';
    csrf.name = 'csrfToken';
    csrf.value = this.csrfToken();
    form.appendChild(csrf);

    document.body.appendChild(form);
    form.submit();
  }

  clearWorkspace(): Observable<void> {
    return this.http
      .post<void>('/api/session/workspace/clear', {}, this.mutationOptions())
      .pipe(tap(() => this.csrfToken.set('')));
  }

  private mutationOptions() {
    return {
      withCredentials: true,
      headers: new HttpHeaders({
        'X-CSRF-Token': this.csrfToken(),
      }),
    };
  }
}
