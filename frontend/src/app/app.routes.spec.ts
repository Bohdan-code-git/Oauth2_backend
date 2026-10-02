import { routes } from './app.routes';

describe('application routes', () => {
  it('has one home route and no separate login or legacy profile routes', () => {
    const explicitPaths = routes
      .filter((route) => route.path !== '**')
      .map((route) => route.path);

    expect(explicitPaths).toEqual(['']);
  });
});
