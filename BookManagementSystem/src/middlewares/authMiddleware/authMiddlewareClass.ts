import { Response, NextFunction } from 'express'
import jwt, { VerifyErrors } from 'jsonwebtoken'
import { AuthenticatedRequest } from '../../interfaces'
import { BaseMiddleware } from 'inversify-express-utils'

import { customErrorHandler } from '../../handler'
import CustomError from '../../helpers/customError'
import { errorCodes } from '../../constants'
import { inject } from 'inversify'

export class JwtAuthenticationMiddleware extends BaseMiddleware {
  // @inject(CustomError) private CustomError : typeof CustomError;
  handler(req: AuthenticatedRequest, res: Response, next: NextFunction): void {
    // Extract the JWT token from the Authorization header
    const authHeader = req.headers.authorization
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      // res.status(errorCodes.UNAUTHORIZED).json({ error: 'Unauthorized' })
      // return
      // const error = {
      //   name: 'TokenNotFoundError'
      // }
      // customErrorHandler(error, req, res, next)
      customErrorHandler(
        new CustomError(
          'UnAuthorized',
          errorCodes.NOT_FOUND,
          'TokenNotFoundError'
        ),
        req,
        res,
        next
      )
      return
    }

    const token = authHeader.slice(7) // Removed 'Bearer ' from the token string

    // Verify the JWT token
    jwt.verify(
      token,
      process.env.JWT_SECRET_KEY as string,
      (err: VerifyErrors | null, decoded: any) => {
        if (err) {
          customErrorHandler(
            new CustomError(
              'UnAuthorized',
              errorCodes.UNAUTHORIZED,
              'JsonWebTokenError'
            ),
            req,
            res,
            next
          )
          return
        }
        // If token is valid, set decoded user data on request object
        req.user = decoded
        next() // Proceed to the next middleware
      }
    )
  }
}
