const jwt = require("jsonwebtoken")

const { generateAccessToken, generateRefreshToken } = require("../utils/token")

exports.refreshToken = (req, res) => {
  const { refreshToken } = req.body

  if (!refreshToken) throw "Unauthorized request"

  try {
    const decode = jwt.verify(refreshToken, process.env.JWT_SECRET_REFRESH)

    const userInfo = {
      id: decode?.id,
      email: decode?.email,
      fullName: decode?.fullName
    }

    const newAccessToken = generateAccessToken(userInfo)
    const newRefreshToken = generateRefreshToken(userInfo)

    res.status(200).json({
      success: true,
      access_token: newAccessToken,
      refresh_token: newRefreshToken,
      message: "Token refreshed successfully"
    })
  } catch (error) {
    res.status(401).json({ error: true, message: "Unauthorized request" })
  }
}
