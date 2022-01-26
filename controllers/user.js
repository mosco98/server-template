const User = require("../models/User")
const bcrypt = require("bcrypt")
const validator = require("validator")
const {
  generateAccessToken,
  generateRefreshToken,
  generateSerializedToken
} = require("../utils/token")

exports.signUp = async (req, res) => {
  // Get request body
  const { fullName, email, password } = req.body

  // Validate request body
  if (validator.isEmpty(fullName)) {
    return res
      .status(400)
      .json({ error: true, message: "Name cannot be empty" })
  }

  if (validator.isEmpty(email)) {
    return res
      .status(400)
      .json({ error: true, message: "Email cannot be empty" })
  }

  if (!validator.isEmail(email)) {
    return res.status(400).json({ error: true, message: "Invalid email" })
  }

  if (validator.isEmpty(password)) {
    return res
      .status(400)
      .json({ error: true, message: "Password cannot be empty" })
  }

  // Check if email already exists in DB
  const userWithEmail = await User.findOne({ where: { email } })

  // if email exists in DB, send response to client
  if (userWithEmail !== null) {
    return res
      .status(400)
      .json({ error: true, message: "User with email already exists" })
  }

  // Hash Password
  bcrypt.genSalt(10, (error, salt) => {
    if (error) {
      return res.status(400).json({ error: true, message: "An error occured" })
    }

    bcrypt.hash(password, salt, async (error, hash) => {
      if (error) {
        return res
          .status(400)
          .json({ error: true, message: "An error occured" })
      }

      // Create new User
      try {
        const user = await User.create({
          fullName,
          email,
          password: hash,
          createdAt: new Date(),
          updatedAt: new Date()
        })

        const accessToken = generateAccessToken({ id: user.id })
        const refreshToken = generateRefreshToken({ id: user.id })

        res.setHeader("Access-Token", generateSerializedToken(accessToken))
        res.setHeader("Refresh-Token", generateSerializedToken(refreshToken))

        return res.status(200).json({
          sucess: true,
          message: "User created successfully",
          id: user.id,
          newUser: true
        })
      } catch (error) {
        return res
          .status(400)
          .json({ error: true, message: "An error occured" })
      }
    })
  })
}

exports.signIn = async (req, res) => {
  // Get request body
  const { email, password } = req.body

  if (validator.isEmpty(email)) {
    return res
      .status(400)
      .json({ error: true, message: "Email cannot be empty" })
  }

  if (!validator.isEmail(email)) {
    return res.status(400).json({ error: true, message: "Invalid email" })
  }

  if (validator.isEmpty(password)) {
    return res
      .status(400)
      .json({ error: true, message: "Password cannot be empty" })
  }

  // Check if email already exists in DB
  const user = await User.findOne({ where: { email } })

  // if email exists in DB, send response to client
  if (user === null) {
    return res
      .status(401)
      .json({ error: true, message: "Sorry, email does not exist" })
  }

  // Check if password match with hash from DB
  const passwordMatch = await bcrypt.compare(password, user.password)

  if (passwordMatch) {
    const accessToken = generateAccessToken({ id: user.id })
    const refreshToken = generateRefreshToken({ id: user.id })

    // res.setHeader("Access-Token", generateSerializedToken(accessToken))
    // res.setHeader("Refresh-Token", generateSerializedToken(refreshToken))

    res.status(202).cookie("Access-Token", accessToken, {
      httpOnly: true,
      sameSite: "strict",
      path: "/"
      // secure: true
    })

    return res.status(200).json({
      sucess: true,
      message: "User signed in successfully",
      id: user.id
    })
  } else {
    return res.status(401).json({ error: true, message: "Incorrect password" })
  }
}

exports.getUser = async (req, res) => {
  const userId = req.headers["userid"]

  const user = await User.findOne({ where: { id: userId } })

  if (user === null) {
    res.status(401).json({ error: true, message: "User does not exist" })
  } else {
    res.status(200).json({
      sucess: true,
      message: "Get user info successful",
      user: {
        id: user.id,
        email: user.email,
        fullName: user.fullName
      }
    })
  }
}
