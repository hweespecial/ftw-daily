const crypto = require('crypto');
const { default: fromKeyLike } = require('jose/jwk/from_key_like');
const { default: SignJWT } = require('jose/jwt/sign');

const radix = 10;
const PORT = parseInt(process.env.REACT_APP_DEV_API_SERVER_PORT, radix);
const rootUrl = process.env.REACT_APP_CANONICAL_ROOT_URL;
const useDevApiServer = process.env.NODE_ENV === 'development' && !!PORT;

const issuerUrl = useDevApiServer ? `http://localhost:${PORT}/api` : `${rootUrl}/api`;

const clientId = 'client-id'; //process.env.CUSTOM_OIDC_CLIENT_ID;

const rsaSecretKey = process.env.RSA_SECRET_KEY;
const rsaPublicKey = process.env.RSA_PUBLIC_KEY;

const privateKey = crypto.createPrivateKey(rsaSecretKey);

exports.openIdConfiguration = (req, res) => {
  res.json({
    issuer: issuerUrl,
    jwks_uri: `${issuerUrl}/.well-known/jwks.json`,
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
  });
};

exports.jwksUri = (req, res) => {
  fromKeyLike(crypto.createPublicKey(rsaPublicKey)).then(jwkPublicKey => {
    res.json({ keys: [{ alg: 'RS256', use: 'sig', ...jwkPublicKey }] });
  });
};

exports.createIdToken = user => {
  if (!user) {
    console.log('No user');
    return;
  }

  const { userId, profile } = user;

  const jwt = new SignJWT({
    firstName: profile.firstName,
    lastName: profile.lastName,
    email: profile.email,
    emailVerified: profile.emailVerified,
  })
    .setProtectedHeader({ alg: 'RS256' })
    .setIssuedAt()
    .setIssuer(issuerUrl)
    .setSubject(userId)
    .setAudience(clientId)
    .setExpirationTime('1h')
    .sign(privateKey);

  return jwt;
};
