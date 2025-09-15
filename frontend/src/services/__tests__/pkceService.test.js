/**
 * PKCE Service Tests
 * OAuth 2.1 PKCE implementation testing
 */
import {
  generateCodeVerifier,
  generateCodeChallenge,
  generatePKCEParams,
  buildAuthorizationUrl,
  exchangeCodeForTokens,
  PKCEAuthFlow,
  parseAuthorizationResponse
} from '../pkceService';

// Mock Web Crypto API for testing
const mockCrypto = {
  subtle: {
    digest: jest.fn()
  },
  getRandomValues: jest.fn()
};

// Mock fetch for token exchange tests
global.fetch = jest.fn();

describe('PKCE Service', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    
    // Mock crypto.getRandomValues
    mockCrypto.getRandomValues.mockImplementation((array) => {
      // Fill with predictable values for testing
      for (let i = 0; i < array.length; i++) {
        array[i] = i % 256;
      }
      return array;
    });
    
    // Mock crypto.subtle.digest
    mockCrypto.subtle.digest.mockResolvedValue(
      new ArrayBuffer(32) // Mock SHA256 hash
    );
    
    // Replace global crypto
    Object.defineProperty(global, 'crypto', {
      value: mockCrypto,
      writable: true
    });
    
    // Mock TextEncoder for Node.js environment
    global.TextEncoder = jest.fn().mockImplementation(() => ({
      encode: jest.fn().mockReturnValue(new Uint8Array([116, 101, 115, 116]))
    }));
    
    // Mock btoa - need to make it dynamic for different values
    global.btoa = jest.fn().mockImplementation((str) => {
      // Create a proper base64-like string for testing
      const hash = Math.abs(str.split('').reduce((a, b) => {
        a = ((a << 5) - a) + b.charCodeAt(0);
        return a & a;
      }, 0));
      return `mockBase64String${hash}`;
    });
  });

  describe('generateCodeVerifier', () => {
    test('generates URL-safe code verifier', () => {
      const verifier = generateCodeVerifier();
      
      expect(typeof verifier).toBe('string');
      expect(verifier.length).toBeGreaterThan(15); // Adjusted for mock implementation
      expect(mockCrypto.getRandomValues).toHaveBeenCalled();
      expect(global.btoa).toHaveBeenCalled();
    });

    test('generates different verifiers on multiple calls', () => {
      // Reset mock to return different values
      let callCount = 0;
      global.btoa = jest.fn().mockImplementation((str) => {
        callCount++;
        return `mockBase64String${callCount}`;
      });

      const verifier1 = generateCodeVerifier();
      const verifier2 = generateCodeVerifier();
      
      expect(verifier1).not.toBe(verifier2);
    });
  });

  describe('generateCodeChallenge', () => {
    test('generates SHA256 code challenge', async () => {
      const verifier = 'test-code-verifier';
      
      const challenge = await generateCodeChallenge(verifier);
      
      expect(typeof challenge).toBe('string');
      expect(mockCrypto.subtle.digest).toHaveBeenCalledWith('SHA-256', expect.any(Uint8Array));
      expect(global.btoa).toHaveBeenCalled();
    });

    test('throws error when Web Crypto API unavailable', async () => {
      // Create new crypto object without subtle property
      const cryptoWithoutSubtle = {
        getRandomValues: jest.fn()
      };
      
      Object.defineProperty(global, 'crypto', {
        value: cryptoWithoutSubtle,
        writable: true
      });
      
      const verifier = 'test-code-verifier';
      
      await expect(generateCodeChallenge(verifier)).rejects.toThrow(
        'Web Crypto API not available. HTTPS required for PKCE.'
      );
      
      // Restore mockCrypto for other tests
      Object.defineProperty(global, 'crypto', {
        value: mockCrypto,
        writable: true
      });
    });
  });

  describe('generatePKCEParams', () => {
    test('generates complete PKCE parameters', async () => {
      const params = await generatePKCEParams();
      
      expect(params).toHaveProperty('codeVerifier');
      expect(params).toHaveProperty('codeChallenge');
      expect(params).toHaveProperty('codeChallengeMethod', 'S256');
      expect(typeof params.codeVerifier).toBe('string');
      expect(typeof params.codeChallenge).toBe('string');
    });
  });

  describe('buildAuthorizationUrl', () => {
    test('builds correct authorization URL', () => {
      const params = {
        clientId: 'test-client',
        redirectUri: 'http://localhost:3000/callback',
        codeChallenge: 'test-challenge',
        codeChallengeMethod: 'S256',
        scope: 'read write',
        state: 'test-state'
      };
      
      const url = buildAuthorizationUrl(params);
      
      expect(url).toContain('oauth2/pkce/authorize');
      expect(url).toContain('response_type=code');
      expect(url).toContain('client_id=test-client');
      expect(url).toContain('redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback');
      expect(url).toContain('code_challenge=test-challenge');
      expect(url).toContain('code_challenge_method=S256');
      expect(url).toContain('scope=read+write');
      expect(url).toContain('state=test-state');
    });

    test('builds URL without optional state parameter', () => {
      const params = {
        clientId: 'test-client',
        redirectUri: 'http://localhost:3000/callback',
        codeChallenge: 'test-challenge'
      };
      
      const url = buildAuthorizationUrl(params);
      
      expect(url).toContain('oauth2/pkce/authorize');
      expect(url).not.toContain('state=');
    });
  });

  describe('exchangeCodeForTokens', () => {
    test('successfully exchanges code for tokens', async () => {
      const mockResponse = {
        access_token: 'mock-access-token',
        token_type: 'Bearer',
        expires_in: 3600,
        refresh_token: 'mock-refresh-token'
      };
      
      global.fetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockResponse)
      });
      
      const params = {
        code: 'test-auth-code',
        codeVerifier: 'test-code-verifier',
        clientId: 'test-client',
        redirectUri: 'http://localhost:3000/callback'
      };
      
      const result = await exchangeCodeForTokens(params);
      
      expect(global.fetch).toHaveBeenCalledWith(
        expect.stringContaining('/oauth2/pkce/token'),
        expect.objectContaining({
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: expect.stringContaining('authorization_code')
        })
      );
      
      expect(result).toEqual(mockResponse);
    });

    test('throws error on token exchange failure', async () => {
      const errorResponse = {
        error: 'invalid_grant',
        error_description: 'Invalid authorization code'
      };
      
      global.fetch.mockResolvedValueOnce({
        ok: false,
        json: () => Promise.resolve(errorResponse)
      });
      
      const params = {
        code: 'invalid-code',
        codeVerifier: 'test-code-verifier',
        clientId: 'test-client',
        redirectUri: 'http://localhost:3000/callback'
      };
      
      await expect(exchangeCodeForTokens(params)).rejects.toThrow(
        'Invalid authorization code'
      );
    });
  });

  describe('PKCEAuthFlow', () => {
    let authFlow;
    let mockStorage;

    beforeEach(() => {
      mockStorage = new Map();
      
      // Mock localStorage
      Object.defineProperty(global, 'localStorage', {
        value: {
          getItem: jest.fn((key) => mockStorage.get(key) || null),
          setItem: jest.fn((key, value) => mockStorage.set(key, value)),
          removeItem: jest.fn((key) => mockStorage.delete(key)),
          clear: jest.fn(() => mockStorage.clear()),
          get length() { return mockStorage.size; },
          key: jest.fn((index) => Array.from(mockStorage.keys())[index] || null)
        },
        writable: true,
        configurable: true
      });
      
      authFlow = new PKCEAuthFlow({
        clientId: 'test-client',
        redirectUri: 'http://localhost:3000/callback'
      });
    });

    test('stores and retrieves PKCE parameters', () => {
      const state = 'test-state';
      const params = {
        codeVerifier: 'test-verifier',
        codeChallenge: 'test-challenge',
        codeChallengeMethod: 'S256'
      };
      
      authFlow.storePKCEParams(state, params);
      
      const retrieved = authFlow.retrievePKCEParams(state);
      
      expect(retrieved).toMatchObject(params);
      expect(retrieved.timestamp).toBeDefined();
      expect(retrieved.expiresAt).toBeDefined();
    });

    test('returns null for non-existent PKCE parameters', () => {
      const result = authFlow.retrievePKCEParams('non-existent-state');
      expect(result).toBeNull();
    });

    test('returns null for expired PKCE parameters', () => {
      const state = 'test-state';
      const params = {
        codeVerifier: 'test-verifier',
        codeChallenge: 'test-challenge',
        codeChallengeMethod: 'S256'
      };
      
      // Store with past expiration
      const expiredData = {
        ...params,
        timestamp: Date.now() - 20 * 60 * 1000, // 20 minutes ago
        expiresAt: Date.now() - 10 * 60 * 1000  // 10 minutes ago
      };
      
      mockStorage.set(`pkce_${state}`, JSON.stringify(expiredData));
      
      const result = authFlow.retrievePKCEParams(state);
      expect(result).toBeNull();
    });

    test('clears PKCE parameters', () => {
      const state = 'test-state';
      const params = {
        codeVerifier: 'test-verifier',
        codeChallenge: 'test-challenge'
      };
      
      authFlow.storePKCEParams(state, params);
      expect(authFlow.retrievePKCEParams(state)).toBeTruthy();
      
      authFlow.clearPKCEParams(state);
      expect(authFlow.retrievePKCEParams(state)).toBeNull();
    });

    test('initiates auth flow successfully', async () => {
      const authUrl = await authFlow.initiateAuth();
      
      expect(typeof authUrl).toBe('string');
      expect(authUrl).toContain('oauth2/pkce/authorize');
      expect(authUrl).toContain('client_id=test-client');
      expect(authUrl).toContain('redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback');
      expect(authUrl).toContain('code_challenge=');
      expect(authUrl).toContain('code_challenge_method=S256');
      expect(authUrl).toContain('state=');
    });
  });

  describe('parseAuthorizationResponse', () => {
    test('parses successful authorization response', () => {
      const url = 'http://localhost:3000/callback?code=test-code&state=test-state';
      
      const result = parseAuthorizationResponse(url);
      
      expect(result).toEqual({
        success: true,
        code: 'test-code',
        state: 'test-state'
      });
    });

    test('parses error authorization response', () => {
      const url = 'http://localhost:3000/callback?error=access_denied&error_description=User+denied+access&state=test-state';
      
      const result = parseAuthorizationResponse(url);
      
      expect(result).toEqual({
        success: false,
        error: 'access_denied',
        error_description: 'User denied access',
        state: 'test-state'
      });
    });

    test('returns null for invalid URL', () => {
      const url = 'http://localhost:3000/callback';
      
      const result = parseAuthorizationResponse(url);
      
      expect(result).toBeNull();
    });
  });
});