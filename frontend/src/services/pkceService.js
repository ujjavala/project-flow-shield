/**
 * PKCE (Proof Key for Code Exchange) Service
 * OAuth 2.1 compliant PKCE implementation for enhanced security
 */

/**
 * Generate cryptographically secure random string
 * @param {number} length - Length of random string
 * @returns {string} URL-safe base64 encoded random string
 */
function generateRandomString(length = 32) {
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);
  return btoa(String.fromCharCode(...array))
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

/**
 * Generate PKCE code verifier
 * RFC 7636 Section 4.1: 43-128 characters, URL-safe
 * @returns {string} Code verifier
 */
export function generateCodeVerifier() {
  return generateRandomString(32);
}

/**
 * Generate PKCE code challenge from verifier
 * RFC 7636 Section 4.2: SHA256 hash of code verifier
 * @param {string} codeVerifier - Code verifier string
 * @returns {Promise<string>} Code challenge (base64url encoded SHA256 hash)
 */
export async function generateCodeChallenge(codeVerifier) {
  if (!crypto.subtle) {
    throw new Error('Web Crypto API not available. HTTPS required for PKCE.');
  }

  const encoder = new TextEncoder();
  const data = encoder.encode(codeVerifier);
  const digest = await crypto.subtle.digest('SHA-256', data);
  
  // Convert to base64url
  return btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

/**
 * Generate PKCE parameters for authorization request
 * @returns {Promise<{codeVerifier: string, codeChallenge: string, codeChallengeMethod: string}>}
 */
export async function generatePKCEParams() {
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = await generateCodeChallenge(codeVerifier);
  
  return {
    codeVerifier,
    codeChallenge,
    codeChallengeMethod: 'S256'
  };
}

/**
 * Build PKCE authorization URL
 * @param {Object} params - Authorization parameters
 * @param {string} params.clientId - OAuth2 client ID
 * @param {string} params.redirectUri - Redirect URI after authorization
 * @param {string} params.codeChallenge - PKCE code challenge
 * @param {string} params.codeChallengeMethod - PKCE code challenge method (S256)
 * @param {string} [params.scope] - Requested scopes
 * @param {string} [params.state] - State parameter for CSRF protection
 * @returns {string} Complete authorization URL
 */
export function buildAuthorizationUrl({
  clientId,
  redirectUri,
  codeChallenge,
  codeChallengeMethod = 'S256',
  scope = 'read write',
  state = null
}) {
  const baseUrl = `${process.env.REACT_APP_API_URL || 'http://localhost:8000'}/oauth2/pkce/authorize`;
  
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: clientId,
    redirect_uri: redirectUri,
    code_challenge: codeChallenge,
    code_challenge_method: codeChallengeMethod,
    scope
  });
  
  if (state) {
    params.append('state', state);
  }
  
  return `${baseUrl}?${params.toString()}`;
}

/**
 * Exchange authorization code for tokens using PKCE
 * @param {Object} params - Token exchange parameters
 * @param {string} params.code - Authorization code
 * @param {string} params.codeVerifier - PKCE code verifier
 * @param {string} params.clientId - OAuth2 client ID
 * @param {string} params.redirectUri - Original redirect URI
 * @returns {Promise<Object>} Token response
 */
export async function exchangeCodeForTokens({
  code,
  codeVerifier,
  clientId,
  redirectUri
}) {
  const tokenUrl = `${process.env.REACT_APP_API_URL || 'http://localhost:8000'}/oauth2/pkce/token`;
  
  const response = await fetch(tokenUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri,
      client_id: clientId,
      code_verifier: codeVerifier
    })
  });
  
  const data = await response.json();
  
  if (!response.ok) {
    throw new Error(data.error_description || `Token exchange failed: ${data.error}`);
  }
  
  return data;
}

/**
 * PKCE-enabled authentication flow
 * Manages the complete OAuth 2.1 PKCE flow with state management
 */
export class PKCEAuthFlow {
  constructor(config = {}) {
    this.clientId = config.clientId || 'demo-client';
    this.redirectUri = config.redirectUri || `${window.location.origin}/callback`;
    this.scope = config.scope || 'read write';
    this.storage = config.useSessionStorage ? sessionStorage : localStorage;
    this.storagePrefix = 'pkce_';
  }

  /**
   * Store PKCE parameters securely
   * @param {string} state - State parameter
   * @param {Object} params - PKCE parameters to store
   */
  storePKCEParams(state, params) {
    const key = `${this.storagePrefix}${state}`;
    const data = {
      ...params,
      timestamp: Date.now(),
      expiresAt: Date.now() + (10 * 60 * 1000) // 10 minutes
    };
    
    this.storage.setItem(key, JSON.stringify(data));
  }

  /**
   * Retrieve and validate stored PKCE parameters
   * @param {string} state - State parameter
   * @returns {Object|null} PKCE parameters or null if not found/expired
   */
  retrievePKCEParams(state) {
    const key = `${this.storagePrefix}${state}`;
    const storedData = this.storage.getItem(key);
    
    if (!storedData) {
      return null;
    }
    
    try {
      const data = JSON.parse(storedData);
      
      // Check expiration
      if (Date.now() > data.expiresAt) {
        this.storage.removeItem(key);
        return null;
      }
      
      return data;
    } catch (error) {
      console.error('Failed to parse stored PKCE params:', error);
      this.storage.removeItem(key);
      return null;
    }
  }

  /**
   * Clear stored PKCE parameters
   * @param {string} state - State parameter
   */
  clearPKCEParams(state) {
    const key = `${this.storagePrefix}${state}`;
    this.storage.removeItem(key);
  }

  /**
   * Initiate PKCE authorization flow
   * @param {Object} options - Additional options
   * @returns {Promise<string>} Authorization URL for redirect
   */
  async initiateAuth(options = {}) {
    try {
      // Generate PKCE parameters
      const pkceParams = await generatePKCEParams();
      
      // Generate state for CSRF protection
      const state = generateRandomString(16);
      
      // Store PKCE parameters
      this.storePKCEParams(state, pkceParams);
      
      // Build authorization URL
      const authUrl = buildAuthorizationUrl({
        clientId: this.clientId,
        redirectUri: this.redirectUri,
        codeChallenge: pkceParams.codeChallenge,
        codeChallengeMethod: pkceParams.codeChallengeMethod,
        scope: options.scope || this.scope,
        state
      });
      
      return authUrl;
    } catch (error) {
      console.error('Failed to initiate PKCE auth flow:', error);
      throw new Error('Authorization flow initialization failed');
    }
  }

  /**
   * Handle authorization callback
   * @param {string} code - Authorization code from callback
   * @param {string} state - State parameter from callback
   * @returns {Promise<Object>} Token response
   */
  async handleCallback(code, state) {
    try {
      // Retrieve stored PKCE parameters
      const pkceParams = this.retrievePKCEParams(state);
      
      if (!pkceParams) {
        throw new Error('Invalid or expired authorization state');
      }
      
      // Exchange code for tokens
      const tokenResponse = await exchangeCodeForTokens({
        code,
        codeVerifier: pkceParams.codeVerifier,
        clientId: this.clientId,
        redirectUri: this.redirectUri
      });
      
      // Clear stored parameters
      this.clearPKCEParams(state);
      
      return tokenResponse;
    } catch (error) {
      console.error('Failed to handle PKCE callback:', error);
      throw error;
    }
  }

  /**
   * Clean up expired PKCE parameters
   */
  cleanupExpiredParams() {
    const keys = [];
    const prefix = this.storagePrefix;
    
    // Find all PKCE keys
    for (let i = 0; i < this.storage.length; i++) {
      const key = this.storage.key(i);
      if (key && key.startsWith(prefix)) {
        keys.push(key);
      }
    }
    
    // Check and remove expired entries
    keys.forEach(key => {
      try {
        const data = JSON.parse(this.storage.getItem(key));
        if (Date.now() > data.expiresAt) {
          this.storage.removeItem(key);
        }
      } catch (error) {
        // Remove invalid entries
        this.storage.removeItem(key);
      }
    });
  }
}

/**
 * Default PKCE auth flow instance
 */
export const pkceAuth = new PKCEAuthFlow({
  clientId: 'demo-client',
  redirectUri: `${window.location.origin}/callback`,
  useSessionStorage: false
});

/**
 * Parse authorization response from URL
 * @param {string} [url] - URL to parse (defaults to current URL)
 * @returns {Object|null} Parsed response with code, state, or error
 */
export function parseAuthorizationResponse(url = window.location.href) {
  try {
    const urlObj = new URL(url);
    const params = new URLSearchParams(urlObj.search);
    
    const code = params.get('code');
    const state = params.get('state');
    const error = params.get('error');
    const errorDescription = params.get('error_description');
    
    if (error) {
      return {
        success: false,
        error,
        error_description: errorDescription,
        state
      };
    }
    
    if (code && state) {
      return {
        success: true,
        code,
        state
      };
    }
    
    return null;
  } catch (error) {
    console.error('Failed to parse authorization response:', error);
    return null;
  }
}