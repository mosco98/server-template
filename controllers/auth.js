const jwt = require("jsonwebtoken")

const {
  generateToken,
  generateRefreshToken,
  generateSerializedToken
} = require("../utils/token")

exports.refreshToken = (req, res, next) => {
  const { refreshToken } = req.body

  if (!refreshToken) throw "Unauthorized request"

  try {
    const userId = jwt.verify(refreshToken, process.env.JWT_SECRET_REFRESH)?.id

    const newAccessToken = generateToken({ id: userId })
    const newRefreshToken = generateRefreshToken({ id: userId })

    res.setHeader("Access-Token", generateSerializedToken(newAccessToken))
    res.setHeader("Refresh-Token", generateSerializedToken(newRefreshToken))

    res.status(200).json({
      success: true,
      message: "Token refreshed successfully"
    })
  } catch (error) {
    next(error)
  }
}
