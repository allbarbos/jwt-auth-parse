const jwt = require("jsonwebtoken");

const messageError = (statusCode, res) => message =>
  res.status(statusCode).send({ error: message });

const authorization = secretOrPublicKey => (req, res, next) => {
  const statusCode = messageError(401, res);

  const auth = req.headers.authorization;

  if (!auth) return statusCode("No token provided");

  const parts = auth.split(" ");

  if (!parts.length === 2) return statusCode("Token error");

  const [scheme, token] = parts;

  if (!/^Bearer$/i.test(scheme)) return statusCode("Token malformatted");

  jwt.verify(token, secretOrPublicKey, (err, decoded) => {
    if (err) return statusCode(`Token invalid: ${err.message}`);
    return next();
  });
};

module.exports = authorization;
