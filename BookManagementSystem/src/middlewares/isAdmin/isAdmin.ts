import { injectable } from 'inversify'
import { NextFunction, Response } from 'express'
import { AuthenticatedRequest } from '../../interfaces'
import { BaseMiddleware } from 'inversify-express-utils'
import { customErrorHandler } from '../../handler'

@injectable()
export class IsAdminMiddleware extends BaseMiddleware {
  async handler(
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
  ): Promise<void> {
    try {
      // const user: User = await UserModel.findOne({ email: req.user.email });
      const user = req.user
      console.log(user)
      if (!user || user.role !== 'admin') {
        const err = {
          name: 'ForbiddenError',
        }
        customErrorHandler(err, req, res, next)
      } else {
        next()
      }
    } catch (error) {
      customErrorHandler(error, req, res, next)
    }
  }
}
