import { Request, Response, NextFunction } from 'express'
import { ParamsDictionary } from 'express-serve-static-core'
import { inject } from 'inversify'
import { BaseMiddleware } from 'inversify-express-utils'
import { ParsedQs } from 'qs'
import customErrorHandler from '../handler/errorHandler'
import { AuthorValidation } from '../validations/authorValidation'
import { CateogoryValidation, UserValidation } from '../validations'
import { BookValidation } from '../validations/bookValidation'

export class ValidatorMiddleWare extends BaseMiddleware {
  private routes: { [key: string]: any }
  constructor(
    @inject(AuthorValidation) private authorValidation: AuthorValidation,
    @inject(CateogoryValidation)
    private categoryValidation: CateogoryValidation,
    @inject(UserValidation) private userValidation: UserValidation,
    @inject(BookValidation) private bookValidation: BookValidation
  ) {
    super()
    this.routes = {
      '/author': this.authorValidation.authorValidationSchema,
      '/category': this.categoryValidation.categoryValidationSchema,
      '/users/signup': this.userValidation.userValidationSchema,
      '/books': this.bookValidation.bookValidationSchema,
    }
  }

  async handler(
    req: Request<ParamsDictionary, any, any, ParsedQs, Record<string, any>>,
    res: Response<any, Record<string, any>>,
    next: NextFunction
  ): Promise<void> {
    try {
      const route = req.path
      const schema = this.routes[route]
      if (Object.values(schema)) {
        await schema.validate(req.body, {
          abortEarly: false,
        })
      }
      next()
    } catch (err) {
      customErrorHandler(err, req, res, next)
    }
  }
}
