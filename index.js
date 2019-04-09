const jwt = require("jsonwebtoken");

const authorization = secretOrPublicKey => {
  return (req, res, next) => {
    const auth = req.headers.authorization;

    if (!auth) return res.status(401).send({ error: "No token provided" });

    const parts = auth.split(" ");

    if (!parts.length === 2)
      return res.status(401).send({ error: "Token error" });

    const [scheme, token] = parts;

    if (!/^Bearer$/i.test(scheme)) {
      return res.status(401).send({ error: "Token malformatted" });
    }

    jwt.verify(token, secretOrPublicKey, (err, decoded) => {
      if (err) return res.status(401).send({ error: "Token invalid" });

      return next();
    });
  };
};

module.exports = authorization;
