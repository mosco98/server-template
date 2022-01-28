const jwt = require("jsonwebtoken")

exports.generateAccessToken = (id) => {
  return jwt.sign(id, process.env.JWT_SECRET_TOKEN, { expiresIn: "5s" })
}

exports.generateRefreshToken = (id) => {
  return jwt.sign(id, process.env.JWT_SECRET_REFRESH, { expiresIn: "7d" })
}

// exports.generateSerializedToken = (token) => {
//   return cookie.serialize("token", token, {
//     httpOnly: true
//   })
// }
