// app.ts
import 'reflect-metadata'
import express from 'express'
import { InversifyExpressServer } from 'inversify-express-utils'
import container from './inversifyConfig'
import swaggerUi from 'swagger-ui-express'
import swaggerDocument from '../swagger.json'
import cookieParser from 'cookie-parser'
import session from 'express-session'
import dotenv from 'dotenv'
import cors from 'cors'
dotenv.config()

// Set up mongoose connection

import { connection } from './config/dbConfig'
const url = process.env.URL

connection(url)

// console.log(process.env)

const port = process.env.PORT || 3000

const app = express()
app.use(cookieParser())
app.use(express.json())
app.use(cors())

app.use(
  session({
    secret: 'your_secret_key', // Replace with a random secret key
    resave: true,
    saveUninitialized: false,
  })
)

// Swagger
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument))

// Set up InversifyExpressServer
const server = new InversifyExpressServer(
  container,
  null,
  { rootPath: '/api' },
  app
)

const appConfigured = server.build()

appConfigured.listen(port, () => {
  console.log('Server is running on port ' + port)
})

export default app;