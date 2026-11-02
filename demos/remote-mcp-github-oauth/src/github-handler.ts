
import { env } from "cloudflare:workers";
import type { AuthRequest, OAuthHelpers } from "@cloudflare/workers-oauth-provider";
import { Hono } from "hono";
import { Octokit } from "octokit";
import { fetchUpstreamAuthToken, getUpstreamAuthorizeUrl, type Props } from "./utils";
import {
	addApprovedClient,
	bindStateToSession,
	createOAuthState,
	generateCSRFProtection,
	isClientApproved,
	OAuthError,
	renderApprovalDialog,
	validateCSRFToken,
	validateOAuthState,
} from "./workers-oauth-utils";

const app = new Hono<{ Bindings: Env & { OAUTH_PROVIDER: OAuthHelpers } }>();

app.get("/authorize", async (c) => {
	const oauthReqInfo = await c.env.OAUTH_PROVIDER.parseAuthRequest(c.req.raw);
	const { clientId } = oauthReqInfo;

	if (!clientId) {
		return c.text("Invalid request", 400);
	}

	// Check if client is already approved.
	if (await isClientApproved(c.req.raw, clientId, env.COOKIE_ENCRYPTION_KEY)) {
		// Skip approval dialog but still create secure state and bind to session.
		const { stateToken } = await createOAuthState(oauthReqInfo, c.env.OAUTH_KV);
		const { setCookie: sessionBindingCookie } = await bindStateToSession(stateToken);

		return redirectToGithub(c.req.raw, stateToken, {
			"Set-Cookie": sessionBindingCookie,
		});
	}

	// Generate CSRF protection for the approval form.
	const { token: csrfToken, setCookie } = generateCSRFProtection();

	return renderApprovalDialog(c.req.raw, {
		client: await c.env.OAUTH_PROVIDER.lookupClient(clientId),
		csrfToken,
		server: {
			description: "Personal MCP server for official Korean legal and statistical data.",
			logo: "https://avatars.githubusercontent.com/u/314135?s=200&v=4",
			name: "Official Data MCP",
		},
		setCookie,
		state: { oauthReqInfo },
	});
});

app.post("/authorize", async (c) => {
	try {
		// Read form data once.
		const formData = await c.req.raw.formData();

		// Validate CSRF token.
		validateCSRFToken(formData, c.req.raw);

		// Extract state from form data.
		const encodedState = formData.get("state");

		if (!encodedState || typeof encodedState !== "string") {
			return c.text("Missing state in form data", 400);
		}

		let state: { oauthReqInfo?: AuthRequest };

		try {
			state = JSON.parse(atob(encodedState));
		} catch (_e) {
			return c.text("Invalid state data", 400);
		}

		if (!state.oauthReqInfo || !state.oauthReqInfo.clientId) {
			return c.text("Invalid request", 400);
		}

		// Add client to approved list.
		const approvedClientCookie = await addApprovedClient(
			c.req.raw,
			state.oauthReqInfo.clientId,
			c.env.COOKIE_ENCRYPTION_KEY,
		);

		// Create OAuth state and bind it to this user's session.
		const { stateToken } = await createOAuthState(
			state.oauthReqInfo,
			c.env.OAUTH_KV,
		);

		const { setCookie: sessionBindingCookie } = await bindStateToSession(
			stateToken,
		);

		// Set both cookies: approved client list + session binding.
		const headers = new Headers();
		headers.append("Set-Cookie", approvedClientCookie);
		headers.append("Set-Cookie", sessionBindingCookie);

		return redirectToGithub(
			c.req.raw,
			stateToken,
			Object.fromEntries(headers),
		);
	} catch (error: any) {
		console.error("POST /authorize error:", error);

		if (error instanceof OAuthError) {
			return error.toResponse();
		}

		return c.text("Internal server error", 500);
	}
});

async function redirectToGithub(
	request: Request,
	stateToken: string,
	headers: Record<string, string> = {},
) {
	return new Response(null, {
		headers: {
			...headers,
			location: getUpstreamAuthorizeUrl({
				client_id: env.GITHUB_CLIENT_ID,
				redirect_uri: new URL("/callback", request.url).href,
				scope: "read:user",
				state: stateToken,
				upstream_url: "https://github.com/login/oauth/authorize",
			}),
		},
		status: 302,
	});
}

/**
 * OAuth Callback Endpoint
 *
 * Handles the callback from GitHub after user authentication.
 *
 * Security checks:
 * 1. Validate the OAuth state against KV storage.
 * 2. Validate the browser session-binding cookie.
 * 3. Exchange the GitHub authorization code for an access token.
 * 4. Retrieve the authenticated GitHub user's numeric ID.
 * 5. Compare that ID with ALLOWED_GITHUB_USER_ID.
 * 6. Issue an MCP OAuth token only when the IDs match.
 */
app.get("/callback", async (c) => {
	let oauthReqInfo: AuthRequest;
	let clearSessionCookie: string;

	try {
		const result = await validateOAuthState(
			c.req.raw,
			c.env.OAUTH_KV,
		);

		oauthReqInfo = result.oauthReqInfo;
		clearSessionCookie = result.clearCookie;
	} catch (error: any) {
		if (error instanceof OAuthError) {
			return error.toResponse();
		}

		return c.text("Internal server error", 500);
	}

	if (!oauthReqInfo.clientId) {
		return c.text("Invalid OAuth request data", 400);
	}

	// Exchange the GitHub authorization code for an access token.
	const [accessToken, errResponse] = await fetchUpstreamAuthToken({
		client_id: c.env.GITHUB_CLIENT_ID,
		client_secret: c.env.GITHUB_CLIENT_SECRET,
		code: c.req.query("code"),
		redirect_uri: new URL("/callback", c.req.url).href,
		upstream_url: "https://github.com/login/oauth/access_token",
	});

	if (errResponse) {
		return errResponse;
	}

	// Fetch the authenticated GitHub user's information.
	let user: Awaited<
		ReturnType<Octokit["rest"]["users"]["getAuthenticated"]>
	>;

	try {
		const octokit = new Octokit({ auth: accessToken });
		user = await octokit.rest.users.getAuthenticated();
	} catch (error) {
		console.error("Failed to retrieve authenticated GitHub user");

		return new Response("GitHub authentication failed", {
			status: 502,
			headers: clearSessionCookie
				? { "Set-Cookie": clearSessionCookie }
				: {},
		});
	}

	// SECURITY: Restrict MCP authorization to the designated GitHub user.
	// Use GitHub's immutable numeric user ID, not the username.
	const allowedUserId = c.env.ALLOWED_GITHUB_USER_ID?.trim();

	if (
		!allowedUserId ||
		!/^\d+$/.test(allowedUserId) ||
		String(user.data.id) !== allowedUserId
	) {
		console.warn("MCP authorization denied: GitHub user ID mismatch");

		return new Response("Access denied: unauthorized GitHub account", {
			status: 403,
			headers: clearSessionCookie
				? { "Set-Cookie": clearSessionCookie }
				: {},
		});
	}

	// The GitHub account has passed the authorization check.
	const { login, name, email } = user.data;

	// Issue an MCP OAuth token only to the authorized GitHub account.
	const { redirectTo } = await c.env.OAUTH_PROVIDER.completeAuthorization({
		metadata: {
			label: name || login,
		},
		props: {
			accessToken,
			email,
			login,
			name,
		} as Props,
		request: oauthReqInfo,
		scope: oauthReqInfo.scope,
		userId: String(user.data.id),
	});

	// Clear the one-time session-binding cookie.
	const headers = new Headers({ Location: redirectTo });

	if (clearSessionCookie) {
		headers.set("Set-Cookie", clearSessionCookie);
	}

	return new Response(null, {
		status: 302,
		headers,
	});
});

export { app as GitHubHandler };
