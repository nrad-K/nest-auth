export default () => ({
  jwt: {
    secret: process.env.JWT_SECRET,
    cookie: {
      maxAge: 3600 * 24 * 30, // 30 days
      secure: process.env.NODE_ENV === 'production', // Only set cookie if in production
    },
    algorithms: ['HS256'],
  },
});
