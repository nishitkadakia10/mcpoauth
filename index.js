const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Environment variables
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const VALID_TOKENS = JSON.parse(process.env.VALID_TOKENS || '{}');
const AUTH_SERVICE_URL = process.env.RAILWAY_PUBLIC_DOMAIN 
  ? `https://${process.env.RAILWAY_PUBLIC_DOMAIN}`
  : process.env.AUTH_SERVICE_URL || 'http://localhost:3001';

// In-memory storage (use Redis/database in production)
const authCodes = new Map();
const clientRegistrations = new Map();

// Cleanup expired codes periodically
setInterval(() => {
  const now = Date.now();
  for (const [code, data] of authCodes.entries()) {
    if (data.expiresAt < now) {
      authCodes.delete(code);
    }
  }
}, 60000); // Every minute

// 1. Server Metadata Discovery
app.get('/.well-known/oauth-authorization-server', (req, res) => {
  console.log('Metadata discovery requested');
  res.json({
    issuer: AUTH_SERVICE_URL,
    authorization_endpoint: `${AUTH_SERVICE_URL}/oauth/authorize`,
    token_endpoint: `${AUTH_SERVICE_URL}/oauth/token`,
    registration_endpoint: `${AUTH_SERVICE_URL}/oauth/register`,
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    response_types_supported: ["code"],
    token_endpoint_auth_methods_supported: ["none"]
  });
});

// 2. Dynamic Client Registration
app.post('/oauth/register', (req, res) => {
  console.log('Client registration request:', req.body);
  
  const clientId = uuidv4();
  const registration = {
    client_id: clientId,
    client_name: req.body.client_name || 'unknown',
    grant_types: req.body.grant_types || ["authorization_code"],
    response_types: req.body.response_types || ["code"],
    token_endpoint_auth_method: req.body.token_endpoint_auth_method || "none",
    scope: req.body.scope || "mcp",
    redirect_uris: req.body.redirect_uris || []
  };
  
  clientRegistrations.set(clientId, registration);
  console.log(`Registered client: ${clientId}`);
  
  res.json(registration);
});

// 3. Authorization Endpoint (with auto-approval for valid tokens)
app.get('/oauth/authorize', (req, res) => {
  console.log('Authorization request:', req.query);
  
  const { 
    client_id, 
    redirect_uri, 
    state, 
    code_challenge,
    code_challenge_method,
    response_type,
    scope 
  } = req.query;
  
  // Get token from query parameter
  const userToken = req.query.token;
  
  // Validate client
  if (!client_id || !clientRegistrations.has(client_id)) {
    console.error('Invalid client_id:', client_id);
    return res.status(400).send('Invalid client_id');
  }
  
  // If no token provided, show a simple form
  if (!userToken) {
    const formHtml = `
      <!DOCTYPE html>
      <html>
      <head>
        <title>MCP Authorization</title>
        <style>
          body { font-family: Arial, sans-serif; max-width: 400px; margin: 50px auto; padding: 20px; }
          .form-group { margin-bottom: 15px; }
          label { display: block; margin-bottom: 5px; }
          input { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }
          button { background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }
          button:hover { background: #0056b3; }
          .error { color: red; margin-bottom: 15px; }
        </style>
      </head>
      <body>
        <h2>MCP Server Authorization</h2>
        <p>Please enter your access token to authorize the connection.</p>
        <form method="POST" action="/oauth/authorize">
          <div class="form-group">
            <label for="token">Access Token:</label>
            <input type="text" id="token" name="token" required placeholder="Enter your unique token">
          </div>
          <input type="hidden" name="client_id" value="${client_id}">
          <input type="hidden" name="redirect_uri" value="${redirect_uri}">
          <input type="hidden" name="state" value="${state}">
          <input type="hidden" name="code_challenge" value="${code_challenge}">
          <input type="hidden" name="code_challenge_method" value="${code_challenge_method}">
          <input type="hidden" name="response_type" value="${response_type}">
          <input type="hidden" name="scope" value="${scope}">
          <button type="submit">Authorize</button>
        </form>
      </body>
      </html>
    `;
    return res.send(formHtml);
  }
  
  // Validate user token
  if (!VALID_TOKENS[userToken]) {
    console.error('Invalid token provided:', userToken);
    // Redirect back with error
    return res.redirect(`${redirect_uri}?error=access_denied&state=${state}`);
  }
  
  // Auto-approve for valid tokens
  const code = crypto.randomBytes(32).toString('hex');
  const userId = VALID_TOKENS[userToken].userId;
  
  // Store auth code with metadata
  authCodes.set(code, {
    clientId: client_id,
    userId: userId,
    userName: VALID_TOKENS[userToken].name || userId,
    codeChallenge: code_challenge,
    codeChallengeMethod: code_challenge_method,
    redirectUri: redirect_uri,
    scope: scope,
    expiresAt: Date.now() + 600000 // 10 minutes
  });
  
  console.log(`Generated auth code for user ${userId}`);
  
  // Redirect back with code
  res.redirect(`${redirect_uri}?code=${code}&state=${state}`);
});

// 3.1 Handle form POST for authorization
app.post('/oauth/authorize', (req, res) => {
  console.log('Authorization form submitted:', req.body);
  
  const { 
    token,
    client_id, 
    redirect_uri, 
    state, 
    code_challenge,
    code_challenge_method,
    response_type,
    scope 
  } = req.body;
  
  // Validate token
  if (!token || !VALID_TOKENS[token]) {
    // Show error page
    const errorHtml = `
      <!DOCTYPE html>
      <html>
      <head>
        <title>Authorization Error</title>
        <style>
          body { font-family: Arial, sans-serif; max-width: 400px; margin: 50px auto; padding: 20px; }
          .error { color: red; }
          a { color: #007bff; }
        </style>
      </head>
      <body>
        <h2>Authorization Error</h2>
        <p class="error">Invalid access token provided.</p>
        <p><a href="/oauth/authorize?${new URLSearchParams(req.body).toString()}">Try again</a></p>
      </body>
      </html>
    `;
    return res.status(401).send(errorHtml);
  }
  
  // Generate auth code
  const code = crypto.randomBytes(32).toString('hex');
  const userId = VALID_TOKENS[token].userId;
  
  // Store auth code
  authCodes.set(code, {
    clientId: client_id,
    userId: userId,
    userName: VALID_TOKENS[token].name || userId,
    codeChallenge: code_challenge,
    codeChallengeMethod: code_challenge_method,
    redirectUri: redirect_uri,
    scope: scope,
    expiresAt: Date.now() + 600000
  });
  
  console.log(`Generated auth code for user ${userId} via form`);
  
  // Redirect back with code
  res.redirect(`${redirect_uri}?code=${code}&state=${state}`);
});

// 4. Token Endpoint
app.post('/oauth/token', (req, res) => {
  console.log('Token request:', req.body);
  
  const { grant_type, code, code_verifier, client_id, refresh_token } = req.body;
  
  if (grant_type === 'authorization_code') {
    const authCode = authCodes.get(code);
    
    if (!authCode) {
      console.error('Invalid authorization code');
      return res.status(400).json({ error: 'invalid_grant' });
    }
    
    if (authCode.expiresAt < Date.now()) {
      console.error('Authorization code expired');
      authCodes.delete(code);
      return res.status(400).json({ error: 'invalid_grant' });
    }
    
    // Verify PKCE if provided
    if (authCode.codeChallenge && code_verifier) {
      const challenge = crypto
        .createHash('sha256')
        .update(code_verifier)
        .digest('base64url');
      
      if (challenge !== authCode.codeChallenge) {
        console.error('PKCE verification failed');
        return res.status(400).json({ error: 'invalid_grant' });
      }
    }
    
    // Generate tokens
    const accessToken = jwt.sign(
      { 
        sub: authCode.userId,
        name: authCode.userName,
        scope: authCode.scope 
      },
      JWT_SECRET,
      { expiresIn: '15m' }
    );
    
    const refreshToken = jwt.sign(
      { 
        sub: authCode.userId,
        name: authCode.userName,
        scope: authCode.scope,
        type: 'refresh'
      },
      JWT_SECRET,
      { expiresIn: '30d' }
    );
    
    // Clean up used code
    authCodes.delete(code);
    
    console.log(`Issued tokens for user ${authCode.userId}`);
    
    res.json({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 900,
      refresh_token: refreshToken,
      scope: authCode.scope || 'mcp'
    });
    
  } else if (grant_type === 'refresh_token') {
    try {
      const decoded = jwt.verify(refresh_token, JWT_SECRET);
      
      if (decoded.type !== 'refresh') {
        return res.status(400).json({ error: 'invalid_grant' });
      }
      
      // Generate new access token
      const accessToken = jwt.sign(
        { 
          sub: decoded.sub,
          name: decoded.name,
          scope: decoded.scope 
        },
        JWT_SECRET,
        { expiresIn: '15m' }
      );
      
      console.log(`Refreshed token for user ${decoded.sub}`);
      
      res.json({
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: 900,
        scope: decoded.scope || 'mcp'
      });
      
    } catch (error) {
      console.error('Invalid refresh token:', error.message);
      return res.status(400).json({ error: 'invalid_grant' });
    }
    
  } else {
    return res.status(400).json({ error: 'unsupported_grant_type' });
  }
});

// Health check
app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    service: 'mcp-auth-service',
    publicUrl: AUTH_SERVICE_URL
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`Auth service listening on port ${PORT}`);
  console.log(`Public URL: ${AUTH_SERVICE_URL}`);
  console.log(`Configured tokens: ${Object.keys(VALID_TOKENS).length}`);
});
