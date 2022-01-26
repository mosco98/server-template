const authRoutes = require("express").Router()
const { refreshToken } = require("../controllers/auth")

authRoutes.post("/refresh-token", refreshToken)

module.exports = authRoutes
