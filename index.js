require("dotenv").config()

const express = require("express")
const app = express()
const cors = require("cors")
const bodyParser = require("body-parser")
const cookieParser = require("cookie-parser")
const db = require("./utils/db")
const userRoutes = require("./routes/user")
const authRoutes = require("./routes/auth")

// Test db connection
db.authenticate()
  .then(() =>
    console.log("Database Connection has been established successfully!")
  )
  .catch((error) => console.error("Unable to connect to the database:", error))

// Middlewares
app.use(cors({ credentials: true, origin: "http://localhost:3000" }))
app.use(bodyParser.json())
app.use(cookieParser())

// API Routes
app.use("/user", userRoutes)
app.use("/auth", authRoutes)

// console.log(require("crypto").randomBytes(64).toString("hex"))

const port = process.env.PORT || 8080

app.listen(port, () => console.log(`Server is now running on port ${port}`))
