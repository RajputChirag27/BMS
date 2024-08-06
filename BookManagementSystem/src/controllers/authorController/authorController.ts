import { NextFunction, Request, Response } from 'express'
import { inject } from 'inversify'
import {
  controller,
  httpGet,
  httpPost,
  httpDelete,
  httpPatch,
  request,
  response,
  next,
} from 'inversify-express-utils'
import { AuthorService } from '../../services/authorService/authorService'
import { AuthenticatedRequest, Author } from '../../interfaces'
import {
  IsAdminMiddleware,
  JwtAuthenticationMiddleware,
  ValidatorMiddleWare,
} from '../../middlewares'
import { errorCodes } from '../../constants'
import { customErrorHandler } from '../../handler'

@controller('/author', JwtAuthenticationMiddleware)
export class AuthorController {
  constructor(@inject(AuthorService) private authorService: AuthorService) {}

  @httpGet('/getAuthors')
  public async getAuthors(
    @request() req: AuthenticatedRequest,
    @response() res: Response,
    @next() next: NextFunction
  ) {
    try {
      const queryObject = { ...req.query }
      const result = await this.authorService.getAuthors(queryObject)
      res.status(result.statusCode).json(result.data)
    } catch (err) {
      customErrorHandler(err, req, res, next)
    }
  }

  @httpPost('/', IsAdminMiddleware, ValidatorMiddleWare)
  public async createAuthor(
    @request() req: AuthenticatedRequest,
    @response() res: Response,
    @next() next: NextFunction
  ) {
    try {
      const author = req.body
      const authors = await this.authorService.createAuthor(author)
      res.send(authors)
    } catch (err) {
      customErrorHandler(err, req, res, next)
    }
  }

  @httpPatch('/updateAuthor/:id')
  async updateAuthor(req: AuthenticatedRequest, res: Response): Promise<void> {
    const id = req.params.id
    const authors = req.body
    try {
      const author: Author = await this.authorService.updateAuthor(id, authors)
      console.log(author)
      if (!author) {
        res.status(errorCodes.NOT_FOUND).json({ error: 'Category not found' })
        return
      }
      res.status(200).json(author)
    } catch (err) {
      customErrorHandler(err, req, res, next)
    }
  }

  @httpDelete('/deleteAuthor/:id')
  async deleteAuthor(req: AuthenticatedRequest, res: Response): Promise<void> {
    const categoryId = req.params.id
    try {
      const deleted = await this.authorService.deleteAuthor(categoryId)
      res.send({ deleted, message: 'Deleted Successfully' })
      if (!deleted) {
        res.status(errorCodes.NOT_FOUND).json({ error: 'Category not found' })
        return
      }
      res.status(errorCodes.NO_CONTENT).end()
    } catch (err) {
      customErrorHandler(err, req, res, next)
    }
  }
}
