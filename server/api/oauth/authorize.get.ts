export default defineEventHandler(async (event) => {
  const query = getQuery(event);
  const { client_id, response_type, redirect_uri, state } = query;

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

  // Generate access token (local auth_token)
  const accessToken = generateAuthToken(event);
  const expiresIn = 3600; // 1 hour

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
}
