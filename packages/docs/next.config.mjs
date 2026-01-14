import nextra from 'nextra'

const withNextra = nextra({
  // Enable default copy code button
  defaultShowCopyCode: true,
})

// Only use static export in production builds
const isProd = process.env.NODE_ENV === 'production'

export default withNextra({
  // Static export configuration for deployment (production only)
  ...(isProd && { output: 'export' }),

  // Required for static export - disable image optimization
  images: {
    unoptimized: true,
  },

  // Add trailing slash for better static hosting compatibility
  trailingSlash: true,

  // React strict mode
  reactStrictMode: true,
})
