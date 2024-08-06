import {
  controller,
  httpDelete,
  httpGet,
  httpPost,
} from 'inversify-express-utils'
import { NextFunction, Request, Response } from 'express'
import UserService from '../../services/userService/userService'
import { inject } from 'inversify'
import { User } from '../../interfaces/index'
import dotenv from 'dotenv'
import { customErrorHandler } from '../../handler'
import { AuthenticatedRequest } from '../../interfaces'
import {
  JwtAuthenticationMiddleware,
  ValidatorMiddleWare,
} from '../../middlewares'
import CustomError from '../../helpers/customError'
import { errorCodes } from '../../constants'
dotenv.config()

@controller('/users')
export class UserController {
  constructor(@inject(UserService) private userService: UserService) {}

  @httpPost('/signup', ValidatorMiddleWare)
  async signup(req: Request, res: Response, next: NextFunction) {
    try {
      const user: User = req.body
      // Hash password
      const hashedPassword: string = await this.userService.hashPassword(
        user.password
      )
      if(!hashedPassword){
        throw new CustomError("Invalid Password", errorCodes.BAD_REQUEST, "Not Created");
      }
      user.password = hashedPassword
      // Create new user
      const newUser = await this.userService.signup(user)
      if(!newUser){
        throw new CustomError("User Not Created", errorCodes.BAD_REQUEST, "Not Created");
      }
      res.status(201).json(newUser)
    } catch (error) {
      customErrorHandler(error, req, res, next)
    }
  }

  @httpPost('/generateOTP')
  async generateOTP(req: any, res: any) {
      try {
          const email: string = req.body.email;
          const length: number = 6; // Default OTP length is 6 digits
          const otp = await this.userService.generateOTP(email, length);
          console.log(otp)
          req.session.user = otp;
          req.session.email = email;
          res.status(200).json({ message : "Email Sent Successfully!!!" });
      } catch (error) {
          console.error('Error generating OTP', error);
          res.status(500).json({ error: 'Internal server error', message: error });
      }
  }


  @httpPost('/login')
  async login(req: Request, res: Response, next: NextFunction) {
    try {
      const user: User = req.body

      const userFromDb = await this.userService.login(user)
      // console.log(userFromDb)
      if (userFromDb) {
        user.role = userFromDb.role
        // console.log(user);
        const payload = user
        // Create a token
        const token = await this.userService.createToken(payload)
        // console.log(token)
        res.send({ userFromDb, token })
      } else {
        res.send('User not found')
      }
    } catch (err) {
      customErrorHandler(err, req, res, next)
    }
  }

  @httpGet('/protected', JwtAuthenticationMiddleware)
  async protected(
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
  ) {
    try {
      res.send('Protected Route')
    } catch (err) {
      customErrorHandler(err, req, res, next)
    }
  }

  @httpDelete('/', JwtAuthenticationMiddleware)
  async deleteUser(
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
  ) {
    try {
      res.send('Protected Route')
    } catch (err) {
      customErrorHandler(err, req, res, next)
    }
  }

  @httpGet("/profile", JwtAuthenticationMiddleware)
  async getUsersProfile(req: AuthenticatedRequest, res: Response, next: NextFunction) {
    try {
      const email = req.user.email;
      console.log(email);
      const user = await this.userService.getUsersById(email);
      if (user) {
        res.send(user);
      }
    } catch (err) {
      if (!res.headersSent)  customErrorHandler(err, req, res, next);
    }
  }

}
