import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideZonelessChangeDetection } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { WorkspaceApi } from './workspace-api.service';

describe('WorkspaceApi', () => {
  let api: WorkspaceApi;
  let requests: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideZonelessChangeDetection(),
        WorkspaceApi,
        provideHttpClient(),
        provideHttpClientTesting(),
      ],
    });
    api = TestBed.inject(WorkspaceApi);
    requests = TestBed.inject(HttpTestingController);
  });

  afterEach(() => requests.verify());

  function initializeWorkspace(): void {
    api.loadWorkspace().subscribe();
    const session = requests.expectOne('/api/session');
    expect(session.request.method).toBe('GET');
    expect(session.request.withCredentials).toBeTrue();
    session.flush({
      application: 'Switchboard', accessMode: 'browser_workspace', mode: 'live', csrfToken: 'csrf-token',
    });
    requests.expectOne('/api/connections').flush({
      demoMode: false, generatedAt: '2026-10-01T12:00:00Z', connections: [],
    });
    requests.expectOne('/api/oauth/providers').flush({ demoMode: false, providers: [] });
  }

  it('loads the browser workspace and all three provider states without an app sign-in gate', () => {
    let result: unknown;
    api.loadWorkspace().subscribe((value) => (result = value));

    requests.expectOne('/api/session').flush({
      application: 'Switchboard', accessMode: 'browser_workspace', mode: 'live', csrfToken: 'csrf-token',
    });
    const connections = requests.expectOne('/api/connections');
    expect(connections.request.withCredentials).toBeTrue();
    connections.flush({ demoMode: false, generatedAt: '2026-10-01T12:00:00Z', connections: [] });
    requests.expectOne('/api/oauth/providers').flush({
      demoMode: false,
      providers: [{
        provider: 'discord', label: 'Discord', configured: true,
        authorizationEndpoint: 'https://discord.com/oauth2/authorize',
        tokenEndpoint: 'https://discord.com/api/oauth2/token',
        callbackUri: 'http://localhost:5223/api/oauth/discord/callback',
        responseType: 'code', scopes: ['identify'],
        pkceMethod: null, profileEndpoints: ['https://discord.com/api/v10/users/@me'],
        authorizationParameters: [{ name: 'prompt', value: 'consent' }],
      }],
    });

    expect(result).toEqual(jasmine.objectContaining({
      demoMode: false,
      connections: [],
      session: jasmine.objectContaining({ accessMode: 'browser_workspace', csrfToken: 'csrf-token' }),
      oauthProviders: [jasmine.objectContaining({ provider: 'discord', configured: true, pkceMethod: null })],
    }));
    requests.expectNone('/api/auth/google/start');
  });

  it('sends the in-memory CSRF token with refresh, disconnect, and workspace clear', () => {
    initializeWorkspace();

    api.refreshConnection('github').subscribe();
    const refresh = requests.expectOne('/api/connections/github/refresh');
    expect(refresh.request.method).toBe('POST');
    expect(refresh.request.headers.get('X-CSRF-Token')).toBe('csrf-token');
    expect(refresh.request.withCredentials).toBeTrue();
    refresh.flush({ demoMode: false, generatedAt: '2026-10-01T12:00:00Z', connections: [] });

    api.disconnect('github').subscribe();
    const disconnect = requests.expectOne('/api/connections/github');
    expect(disconnect.request.method).toBe('DELETE');
    expect(disconnect.request.headers.get('X-CSRF-Token')).toBe('csrf-token');
    disconnect.flush(null);

    api.clearWorkspace().subscribe();
    const clear = requests.expectOne('/api/session/workspace/clear');
    expect(clear.request.method).toBe('POST');
    expect(clear.request.headers.get('X-CSRF-Token')).toBe('csrf-token');
    clear.flush(null);
  });

  it('starts provider OAuth as a CSRF-protected top-level form navigation', () => {
    initializeWorkspace();
    const submit = spyOn(HTMLFormElement.prototype, 'submit').and.stub();

    api.startProvider('discord');

    const form = document.body.querySelector('form[action="/api/connections/discord/start"]') as HTMLFormElement;
    expect(form).not.toBeNull();
    expect(form.method).toBe('post');
    expect((form.querySelector('input[name="csrfToken"]') as HTMLInputElement).value).toBe('csrf-token');
    expect(submit).toHaveBeenCalledTimes(1);
    form.remove();
  });
});
