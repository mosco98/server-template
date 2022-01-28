const userRoutes = require("express").Router()

const { signIn, signUp, getUser, getNote } = require("../controllers/user")
const { isAuthenticated } = require("../middlewares/auth")

// Routes
userRoutes.get("/", isAuthenticated, getUser)
userRoutes.get("/get-note", isAuthenticated, getNote)

userRoutes.post("/signin", signIn)
userRoutes.post("/signup", signUp)

module.exports = userRoutes
