/**
 * Window event names shared across the data layer and the auth layer. Kept in their own file
 * (rather than defined in realApiProvider.ts and imported from there) so nothing outside the
 * data layer needs to import a specific provider implementation just to reference an event name
 * -- components/pages always go through DataProvider/useDataProvider(), never a concrete
 * provider class directly.
 */

/**
 * Dispatched by RealApiProvider whenever an authenticated request gets a 401 that isn't the
 * expected "wrong password" (/auth/login) or "no session yet" (/auth/me) case -- i.e. an
 * existing session just expired mid-use. session.tsx listens for this and clears its analyst
 * state, which RequireSession.tsx turns into a redirect to /login for free.
 */
export const SESSION_EXPIRED_EVENT = "netshield:session-expired";
