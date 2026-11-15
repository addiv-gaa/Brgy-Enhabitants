import axios from "axios"

const api = axios.create({
    baseURL: import.meta.env.VITE_API_URL,
    withCredentials: true,  // Send HttpOnly cookies with every request
    xsrfCookieName: 'csrftoken',
    xsrfHeaderName: 'X-CSRFToken',
})

// Helper to extract CSRF token from document.cookie for same-origin or trusted SPA requests
function getCsrfToken(): string | null {
    if (typeof document === 'undefined') return null;
    const match = document.cookie.match(/(?:^|;\s*)csrftoken=([^;]+)/);
    return match ? decodeURIComponent(match[1]) : null;
}

// Request interceptor: attach X-CSRFToken and Bearer token fallback for Safari/iOS (F-029)
api.interceptors.request.use((config) => {
    const csrfToken = getCsrfToken();
    if (csrfToken && !config.headers['X-CSRFToken']) {
        config.headers['X-CSRFToken'] = csrfToken;
    }
    const token = sessionStorage.getItem('access_token');
    if (token && !config.headers['Authorization']) {
        config.headers['Authorization'] = `Bearer ${token}`;
    }
    return config;
});

let isRefreshing = false;
let failedQueue: { resolve: (value?: unknown) => void; reject: (reason?: unknown) => void }[] = [];

const processQueue = (error: unknown) => {
    failedQueue.forEach(prom => {
        if (error) {
            prom.reject(error);
        } else {
            prom.resolve();
        }
    });
    failedQueue = [];
};

const PUBLIC_PATHS = [
    '/',
    '/login',
    '/register',
    '/announcements',
    '/emergencycontacts',
    '/barangayofficials',
    '/resident/schedule',
    '/aiassistant'
];

api.interceptors.response.use(
    (response) => response,
    async (error) => {
        const originalRequest = error.config;

        // F-016: If the login endpoint itself failed, do NOT attempt token refresh!
        // Return the error directly so Form.tsx displays "Invalid Credentials" or lockout message.
        if (originalRequest?.url?.includes('/api/token/') && !originalRequest.url?.includes('/api/token/refresh/')) {
            return Promise.reject(error);
        }

        // F-031: If checking initial auth status (/api/auth/me/) and user is not logged in, reject cleanly without refresh loop
        if (originalRequest?.url?.includes('/api/auth/me/')) {
            return Promise.reject(error);
        }

        if (error.response?.status === 401 && !originalRequest._retry) {
            // If the refresh endpoint itself failed, redirect to login if on protected page
            if (originalRequest.url?.includes('/api/token/refresh/')) {
                const currentPath = window.location.pathname;
                const isPublic = PUBLIC_PATHS.some(p => currentPath === p || (p !== '/' && currentPath.startsWith(p)));
                if (!isPublic) {
                    window.location.href = '/login';
                }
                return Promise.reject(error);
            }

            // If another refresh is already in progress, queue this request
            if (isRefreshing) {
                return new Promise(function (resolve, reject) {
                    failedQueue.push({ resolve, reject });
                }).then(() => {
                    return api(originalRequest);
                }).catch(err => {
                    return Promise.reject(err);
                });
            }

            originalRequest._retry = true;
            isRefreshing = true;

            try {
                // Refresh session using HttpOnly cookie credentials and Bearer fallback for Safari/iOS (F-029)
                const refreshToken = sessionStorage.getItem('refresh_token');
                const res = await axios.post(
                    import.meta.env.VITE_API_URL + '/api/token/refresh/',
                    { refresh: refreshToken || undefined },
                    { withCredentials: true }
                );

                if (res.data?.access) {
                    sessionStorage.setItem('access_token', res.data.access);
                    originalRequest.headers = originalRequest.headers || {};
                    originalRequest.headers['Authorization'] = `Bearer ${res.data.access}`;
                }

                processQueue(null);

                // Retry original request with refreshed credentials
                return api(originalRequest);
            } catch (err) {
                processQueue(err);

                // Clear any expired tokens
                sessionStorage.removeItem('access_token');
                sessionStorage.removeItem('refresh_token');

                // F-031: ONLY redirect if we are on a protected page
                const currentPath = window.location.pathname;
                const isPublic = PUBLIC_PATHS.some(p => currentPath === p || (p !== '/' && currentPath.startsWith(p)));
                if (!isPublic) {
                    window.location.href = '/login';
                }
                return Promise.reject(err);
            } finally {
                isRefreshing = false;
            }
        }

        return Promise.reject(error);
    }
)

export default api
