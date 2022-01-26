const jwt = require("jsonwebtoken")
const cookie = require("cookie")

exports.generateAccessToken = (id) => {
  return jwt.sign(id, process.env.JWT_SECRET_TOKEN, { expiresIn: "3600s" })
}

exports.generateRefreshToken = (id) => {
  return jwt.sign(id, process.env.JWT_SECRET_REFRESH, { expiresIn: "7d" })
}

exports.generateSerializedToken = (token) => {
  return cookie.serialize("token", token, {
    httpOnly: true
  })
}
