import { provideZonelessChangeDetection } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { of, throwError } from 'rxjs';
import { ConnectionDto, ConnectionsResponse, WorkspaceApi } from '../workspace-api.service';
import { Home } from './home';

const providers: ConnectionDto[] = [
  {
    provider: 'google', label: 'Google', status: 'not_connected', configured: true,
    profile: null, connectedAt: null, lastSyncedAt: null, accessTokenExpiresAt: null,
    canRefreshAccessToken: false, grantedScopes: [], message: null,
  },
  {
    provider: 'discord', label: 'Discord', status: 'connected', configured: true,
    profile: {
      displayName: 'Mira Dev', identifier: 'mira.dev', email: null,
      avatarUrl: 'https://cdn.discordapp.com/avatars/4815162342/avatarhash.png',
      profileUrl: 'https://discord.com/users/4815162342',
    }, connectedAt: '2026-09-30T12:00:00Z', lastSyncedAt: '2026-10-01T12:00:00Z',
    accessTokenExpiresAt: new Date(Date.now() + 5 * 60_000).toISOString(),
    canRefreshAccessToken: true,
    grantedScopes: ['identify'],
    message: null,
  },
  {
    provider: 'github', label: 'GitHub', status: 'reauth_required', configured: true,
    profile: {
      displayName: 'bogdan-dev', identifier: 'bogdan-dev', email: null,
      avatarUrl: null, profileUrl: 'https://github.com/bogdan-dev',
    }, connectedAt: '2026-09-30T12:00:00Z', lastSyncedAt: '2026-09-30T12:05:00Z',
    accessTokenExpiresAt: null,
    canRefreshAccessToken: false,
    grantedScopes: [],
    message: 'Authorization is required again.',
  },
];

const snapshot: ConnectionsResponse = {
  demoMode: false,
  generatedAt: '2026-10-01T12:00:00Z',
  connections: providers,
  session: {
    application: 'Switchboard',
    accessMode: 'browser_workspace',
    mode: 'live',
    csrfToken: 'csrf-token',
  },
  oauthProviders: [{
    provider: 'discord', label: 'Discord', configured: true,
    authorizationEndpoint: 'https://discord.com/oauth2/authorize',
    tokenEndpoint: 'https://discord.com/api/oauth2/token',
    callbackUri: 'http://localhost:5223/api/oauth/discord/callback',
    responseType: 'code', scopes: ['identify'],
    pkceMethod: null, profileEndpoints: ['https://discord.com/api/v10/users/@me'],
    authorizationParameters: [{ name: 'prompt', value: 'consent' }],
  }],
};

function createHome(api: jasmine.SpyObj<WorkspaceApi>) {
  TestBed.configureTestingModule({
    imports: [Home],
    providers: [
      provideZonelessChangeDetection(),
      { provide: WorkspaceApi, useValue: api },
    ],
  });
  const fixture = TestBed.createComponent(Home);
  fixture.detectChanges();
  return fixture;
}

describe('Home', () => {
  it('shows a separate sign-in action for each provider', () => {
    const api = jasmine.createSpyObj<WorkspaceApi>('WorkspaceApi', ['loadWorkspace', 'refreshConnection', 'disconnect', 'startProvider']);
    api.loadWorkspace.and.returnValue(of(snapshot));
    const fixture = createHome(api);
    const element = fixture.nativeElement as HTMLElement;

    expect(element.querySelector('h1')?.textContent?.trim()).toBe('Connected accounts');
    expect(Array.from(element.querySelectorAll('.connection-card h2')).map((heading) => heading.textContent?.trim()))
      .toEqual(['Google', 'GitHub', 'Discord']);
    expect(element.querySelectorAll('.connection-card').length).toBe(3);
    expect(element.querySelector('.topbar-note')).toBeNull();
    expect(element.querySelector('.setup-details')).toBeNull();
    expect(element.querySelector('a[href="/api/auth/google/start"]')).toBeNull();
    expect(element.textContent).not.toContain('Sign in to Switchboard first');
  });

  it('shows connection status, the configured OAuth contract, and only safe token lifecycle metadata', () => {
    const api = jasmine.createSpyObj<WorkspaceApi>('WorkspaceApi', ['loadWorkspace', 'refreshConnection', 'disconnect', 'startProvider']);
    api.loadWorkspace.and.returnValue(of(snapshot));
    const fixture = createHome(api);
    const element = fixture.nativeElement as HTMLElement;
    const discord = element.querySelector('[data-provider="discord"]') as HTMLElement;

    expect(element.querySelector('.connection-summary')?.textContent).toContain('Connected');
    expect(element.querySelector('.connection-summary')?.textContent).toContain('1 / 3');
    expect(element.querySelector('.connection-summary')?.textContent).toContain('Needs attention');
    expect(element.querySelector('.connection-summary')?.textContent).toContain('Can refresh');
    expect(discord.querySelector('.oauth-inspector')?.textContent).toContain('Authorization Code');
    const pkceFact = Array.from(discord.querySelectorAll('.oauth-facts > div'))
      .find((fact) => fact.querySelector('dt')?.textContent === 'PKCE');
    expect(pkceFact?.querySelector('dd')?.textContent).toBe('Not used in this provider flow');
    expect(discord.querySelector('.oauth-inspector')?.textContent).toContain('http://localhost:5223/api/oauth/discord/callback');
    expect(discord.querySelector('.oauth-inspector')?.textContent).toContain('identify');
    expect(discord.querySelector('.oauth-inspector')?.textContent).toContain('Available');
    expect(discord.querySelector('.oauth-inspector')?.textContent).toContain('Access expires');
    expect(discord.textContent).not.toContain('discord access token');
  });

  it('uses concise product copy and explains token handling once', () => {
    const api = jasmine.createSpyObj<WorkspaceApi>('WorkspaceApi', ['loadWorkspace', 'refreshConnection', 'disconnect', 'startProvider']);
    api.loadWorkspace.and.returnValue(of(snapshot));
    const fixture = createHome(api);
    const element = fixture.nativeElement as HTMLElement;
    const intro = element.querySelector('.intro')?.textContent ?? '';

    expect(intro).toContain('Connect your own Google, GitHub, and Discord accounts');
    expect(intro).toContain('One-time state per provider');
    expect(intro).toContain('Tokens stay on the server');
    expect(element.querySelector('.connection-summary h2')?.textContent?.trim()).toBe('Connection status');
    expect(element.querySelector('.security-note')).toBeNull();
    expect(element.textContent).not.toContain('Live workspace state');
    expect(element.textContent).not.toContain('OAuth grant health');
    expect(element.textContent).not.toContain('Counts come from this browser');
  });

  it('starts a separate provider flow from each card', () => {
    const api = jasmine.createSpyObj<WorkspaceApi>('WorkspaceApi', ['loadWorkspace', 'refreshConnection', 'disconnect', 'startProvider']);
    api.loadWorkspace.and.returnValue(of(snapshot));
    const fixture = createHome(api);
    const buttons = Array.from(fixture.nativeElement.querySelectorAll('.connection-card button.connect-action')) as HTMLButtonElement[];

    expect(buttons.map((button) => button.textContent?.trim())).toEqual([
      'Connect Google', 'Reconnect GitHub', 'Connect Discord',
    ]);
    buttons.forEach((button) => button.click());
    expect(api.startProvider.calls.allArgs()).toEqual([['google'], ['github'], ['discord']]);
  });

  it('lets the user verify a live provider grant through the server-side profile request', () => {
    const api = jasmine.createSpyObj<WorkspaceApi>('WorkspaceApi', ['loadWorkspace', 'refreshConnection', 'disconnect', 'startProvider']);
    api.loadWorkspace.and.returnValue(of(snapshot));
    api.refreshConnection.and.returnValue(of(snapshot));
    const fixture = createHome(api);
    const discord = fixture.nativeElement.querySelector('[data-provider="discord"]') as HTMLElement;
    const verify = discord.querySelector('.verify-grant') as HTMLButtonElement;

    expect(verify.textContent?.trim()).toBe('Check grant');
    verify.click();
    expect(api.refreshConnection).toHaveBeenCalledOnceWith('discord');
  });

  it('copies the callback URL supplied by the backend for provider console setup', async () => {
    const api = jasmine.createSpyObj<WorkspaceApi>('WorkspaceApi', ['loadWorkspace', 'refreshConnection', 'disconnect', 'startProvider']);
    api.loadWorkspace.and.returnValue(of(snapshot));
    const fixture = createHome(api);
    const writeText = jasmine.createSpy('writeText').and.resolveTo();
    spyOnProperty(navigator, 'clipboard', 'get').and.returnValue({ writeText } as unknown as Clipboard);

    await (fixture.componentInstance as Home).copyCallback('discord');
    fixture.detectChanges();

    expect(writeText).toHaveBeenCalledOnceWith('http://localhost:5223/api/oauth/discord/callback');
    expect(fixture.nativeElement.querySelector('[role="status"]')?.textContent).toContain('Callback URL copied');
  });

  it('shows the profile returned by the provider and the account that needs reauthorization', () => {
    const api = jasmine.createSpyObj<WorkspaceApi>('WorkspaceApi', ['loadWorkspace', 'refreshConnection', 'disconnect', 'startProvider']);
    api.loadWorkspace.and.returnValue(of(snapshot));
    const fixture = createHome(api);
    const discord = fixture.nativeElement.querySelector('[data-provider="discord"]') as HTMLElement;
    const github = fixture.nativeElement.querySelector('[data-provider="github"]') as HTMLElement;

    expect(discord.textContent).toContain('Mira Dev');
    expect(discord.textContent).toContain('mira.dev');
    expect(discord.textContent).toContain('Connected');
    expect(github.textContent).toContain('bogdan-dev');
    expect(github.textContent).toContain('Needs authorization');
    expect(github.querySelector('.connect-action')?.textContent).toContain('Reconnect GitHub');
  });

  it('does not print a Google email twice as both identifier and email', () => {
    const api = jasmine.createSpyObj<WorkspaceApi>('WorkspaceApi', ['loadWorkspace', 'refreshConnection', 'disconnect', 'startProvider']);
    api.loadWorkspace.and.returnValue(of({
      ...snapshot,
      connections: [
        {
          ...providers[0],
          status: 'connected',
          profile: {
            displayName: 'Creator', identifier: 'creator@example.test', email: 'creator@example.test',
            avatarUrl: null, profileUrl: null,
          },
        },
        providers[1],
        providers[2],
      ],
    }));
    const fixture = createHome(api);
    const google = fixture.nativeElement.querySelector('[data-provider="google"]') as HTMLElement;

    expect(google.querySelectorAll('.profile-detail').length).toBe(1);
    expect(google.querySelector('.profile-detail')?.textContent).toBe('creator@example.test');
    expect(google.querySelector('.profile-name')?.textContent).toBe('Creator');
  });

  it('asks the user to reconnect when saved connection data cannot be restored', () => {
    const api = jasmine.createSpyObj<WorkspaceApi>('WorkspaceApi', ['loadWorkspace', 'refreshConnection', 'disconnect', 'startProvider']);
    api.loadWorkspace.and.returnValue(of({
      ...snapshot,
      session: { ...snapshot.session!, workspaceRecoveryRequired: true },
    }));
    const fixture = createHome(api);

    expect(fixture.nativeElement.querySelector('[role="alert"]')?.textContent)
      .toContain('Could not restore saved connection data');
    expect(fixture.nativeElement.textContent).toContain('Reconnect your accounts');
  });

  it('never presents a fictional account when credentials are absent', () => {
    const unconfigured: ConnectionsResponse = {
      ...snapshot,
      demoMode: true,
      connections: providers.map((provider) => ({
        ...provider,
        status: 'not_configured',
        configured: false,
        profile: null,
        connectedAt: null,
        lastSyncedAt: null,
      })),
      oauthProviders: [],
    };
    const api = jasmine.createSpyObj<WorkspaceApi>('WorkspaceApi', ['loadWorkspace', 'refreshConnection', 'disconnect', 'startProvider']);
    api.loadWorkspace.and.returnValue(of(unconfigured));
    const fixture = createHome(api);
    const cards = Array.from(fixture.nativeElement.querySelectorAll('.connection-card')) as HTMLElement[];

    expect(fixture.nativeElement.textContent).toContain('Demo mode');
    expect(cards.every((card) => card.textContent?.includes('Not configured'))).toBeTrue();
    expect(cards.every((card) => card.textContent?.includes('No account connected'))).toBeTrue();
    expect(fixture.nativeElement.textContent).not.toContain('Example Google account');
  });

  it('shows callback errors safely and removes OAuth parameters from the address bar', () => {
    const api = jasmine.createSpyObj<WorkspaceApi>('WorkspaceApi', ['loadWorkspace', 'refreshConnection', 'disconnect', 'startProvider']);
    api.loadWorkspace.and.returnValue(of(snapshot));
    window.history.replaceState({}, '', '/?oauth=error&provider=discord&reason=access_denied&code=secret#top');
    const fixture = createHome(api);

    expect(fixture.nativeElement.querySelector('[role="alert"]')?.textContent).toContain('Discord access was not approved');
    expect(window.location.search).toBe('');
    expect(window.location.hash).toBe('#top');
    expect(fixture.nativeElement.textContent).not.toContain('secret');
  });

  it('offers a retry when the workspace request fails', () => {
    const api = jasmine.createSpyObj<WorkspaceApi>('WorkspaceApi', ['loadWorkspace', 'refreshConnection', 'disconnect', 'startProvider']);
    api.loadWorkspace.and.returnValue(throwError(() => new Error('network error')));
    const fixture = createHome(api);

    expect(fixture.nativeElement.querySelector('[role="alert"]')?.textContent).toContain('could not load');
    const retry = fixture.nativeElement.querySelector('button.retry-action') as HTMLButtonElement;
    expect(retry).not.toBeNull();
    api.loadWorkspace.and.returnValue(of(snapshot));
    retry.click();
    fixture.detectChanges();

    expect(api.loadWorkspace).toHaveBeenCalledTimes(2);
    expect(fixture.nativeElement.querySelectorAll('.connection-card').length).toBe(3);
  });
});
