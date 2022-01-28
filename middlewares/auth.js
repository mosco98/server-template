const jwt = require("jsonwebtoken")

exports.isAuthenticated = (req, res, next) => {
  const authHeader = req.headers["authorization"]
  const userId = req.headers["userid"]
  const accessToken = authHeader && authHeader.split(" ")[1]

  if (accessToken === null) {
    return res
      .status(401)
      .json({ error: true, message: "Unauthorized request" })
  }

  try {
    const decoded = jwt.verify(accessToken, process.env.JWT_SECRET_TOKEN)

    if (decoded?.id !== userId) {
      return res.status(401).json({ error: true, message: "Invalid user ID" })
    } else {
      next()
    }
  } catch (error) {
    return res
      .status(401)
      .json({ error: true, message: "Unauthorized request" })
  }
}
