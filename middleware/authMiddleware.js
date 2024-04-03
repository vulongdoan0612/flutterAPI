// middleware/authMiddleware.js

import jwt from "jsonwebtoken";

export const checkAccessToken = (req, res, next) => {
  const accessToken = req.headers.authorization || req.cookies.accessToken;
  console.log(req.headers.authorization, "test");
  if (!accessToken) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  try {
    const decoded = jwt.verify(accessToken, "VinalinkGroup!2020");
    req.user = decoded;
    next();
  } catch (error) {
    console.log(error);
    return res.status(401).json({ message: "Invalid AccessToken" });
  }
};
