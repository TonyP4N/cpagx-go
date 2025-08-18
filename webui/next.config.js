/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'export',
  trailingSlash: true,
  images: {
    unoptimized: true
  },
  async rewrites() {
    return [
      { source: '/api/v1/:path*', destination: 'http://localhost:8080/api/v1/:path*' },
      { source: '/api/v2/:path*', destination: 'http://localhost:8080/api/v2/:path*' },
      { source: '/api/version/:path*', destination: 'http://localhost:8080/api/version/:path*' },
      { source: '/api/tasks/:path*', destination: 'http://localhost:8080/api/tasks/:path*' },
      { source: '/api/cpag/:path*', destination: 'http://localhost:8080/api/cpag/:path*' },
      { source: '/api/graph/:path*', destination: 'http://localhost:8080/api/graph/:path*' },
      { source: '/api/health', destination: 'http://localhost:8080/api/health' }
    ];
  },
};

module.exports = nextConfig;
