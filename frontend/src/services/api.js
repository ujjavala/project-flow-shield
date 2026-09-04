import axios from 'axios';
import { csrfHeaders } from './bffService';

const baseURL = import.meta.env.VITE_API_URL || '';
let refreshPromise = null;

// Create axios instance
const api = axios.create({
  baseURL,
  timeout: 10000,
  withCredentials: true,
  headers: {
    'Content-Type': 'application/json',
  },
});

// BFF sessions are HttpOnly; JavaScript adds only the session-bound CSRF value.
api.interceptors.request.use(
  (config) => {
    config.headers = csrfHeaders(config.headers);
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor for token refresh
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    if (error.response?.status === 401 && !originalRequest?._retry && !originalRequest?.url?.startsWith('/bff/')) {
      originalRequest._retry = true;

      try {
        if (!refreshPromise) {
          refreshPromise = axios.post(
            `${baseURL}/bff/refresh`,
            {},
            { withCredentials: true, headers: csrfHeaders() },
          ).finally(() => {
            refreshPromise = null;
          });
        }
        await refreshPromise;
        return api(originalRequest);
      } catch (refreshError) {
        window.location.href = '/login';
        return Promise.reject(refreshError);
      }
    }

    return Promise.reject(error);
  }
);

export default api;