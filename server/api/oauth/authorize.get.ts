export default defineEventHandler(async (event) => {
  const query = getQuery(event);
  let { client_id, response_type, redirect_uri, state } = query;

  // Check if there's a saved OAuth state from login redirect
  const savedOAuthState = getCookie(event, "oauth_request_state");
  if (savedOAuthState && !client_id) {
    try {
      const parsedState = JSON.parse(savedOAuthState);
      client_id = parsedState.client_id;
      response_type = parsedState.response_type;
      redirect_uri = parsedState.redirect_uri;
      state = parsedState.state;
    } catch (e) {
      // Invalid saved state, ignore and proceed with query params
    }
  }

  // Validate required parameters
  if (!client_id || !response_type) {
    return sendError(
      event,
      createError({
        statusCode: 400,
        statusMessage: "Missing required parameters: client_id, response_type",
      })
    );
  }

  // Validate response_type is "token" for implicit flow
  if (response_type !== "token") {
    return sendError(
      event,
      createError({
        statusCode: 400,
        statusMessage: "Invalid response_type. Expected 'token' for implicit flow",
      })
    );
  }

  // Get valid client IDs from environment
  const validClientIds = (process.env.OAUTH_VALID_CLIENT_IDS || "")
    .split(",")
    .map((id) => id.trim());

  // Validate client_id
  if (!validClientIds.includes(client_id as string)) {
    return sendError(
      event,
      createError({
        statusCode: 401,
        statusMessage: "Invalid client_id",
      })
    );
  }

  // Check if user is logged in by checking auth token
  const authToken = getCookie(event, "semi_auth_token");

  if (!authToken) {
    // User is not logged in, save OAuth request state and redirect to login
    const oauthState = {
      client_id,
      response_type,
      redirect_uri,
      state,
      timestamp: Date.now(),
    };

    // Save OAuth request state in cookie (expires in 10 minutes)
    setCookie(event, "oauth_request_state", JSON.stringify(oauthState), {
      maxAge: 600, // 10 minutes
      httpOnly: false,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      path: "/",
    });

    // Redirect to login page with oauth flag
    return sendRedirect(event, "/login?redirect=oauth");
  }

  // User is logged in, proceed with OAuth token generation
  const accessToken = generateAuthToken(event);
  const expiresIn = 3600; // 1 hour

  // Clear the OAuth state cookie if it exists
  setCookie(event, "oauth_request_state", "", {
    maxAge: -1, // Delete cookie
    httpOnly: false,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
  });

  // If redirect_uri is provided, redirect with token in fragment
  if (redirect_uri) {
    const redirectUrl = new URL(redirect_uri as string);
    redirectUrl.hash = `access_token=${accessToken}&token_type=Bearer&expires_in=${expiresIn}`;
    if (state) {
      redirectUrl.hash += `&state=${state}`;
    }
    return sendRedirect(event, redirectUrl.toString());
  }

  // Otherwise return token directly
  return {
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: expiresIn,
    state: state || undefined,
  };
});

/**
 * Generate a local auth token
 * Returns existing auth_token from cookie if available, otherwise generates a new one
 */
function generateAuthToken(event: any): string {
  // Try to get existing auth token from cookie
  const existingToken = getCookie(event, "semi_auth_token");
  if (existingToken) {
    return existingToken;
  }

  // Generate a new token if not found (fallback)
  const timestamp = Date.now();
  const random = Math.random().toString(36).substring(2, 15);
  return `auth_${timestamp}_${random}`;
}
